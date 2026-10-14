package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// inventoryHTTP owns the inventory protocol; storage adapters implement complete
// atomic domain operations, with no HTTP, authentication, or JSON knowledge.
type inventoryHTTP struct {
	store    inventory.Store
	verifier *serviceauth.Verifier
}

func inventoryHandler(store inventory.Store, key sshcert.RawPublicKey) (http.Handler, error) {
	v, err := serviceauth.NewVerifierFor(key, serviceauth.InventoryAudience)
	if err != nil {
		return nil, err
	}
	h := &inventoryHTTP{store: store, verifier: v}
	mux := http.NewServeMux()
	mux.HandleFunc("/lookup", h.discovery)
	mux.HandleFunc("/inventory/records", h.serve)
	mux.HandleFunc("/inventory/records/{id}", h.serve)
	mux.HandleFunc("/inventory/tokens", h.serve)
	mux.HandleFunc("/inventory/audit", h.serve)
	return mux, nil
}
func (h *inventoryHTTP) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "OPTIONS" {
		http.NotFound(w, r)
		return
	}
	if _, err := h.verifier.VerifyActor(r, nil); err != nil {
		http.Error(w, "invalid control authentication", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Allow", "GET, OPTIONS")
	w.Header().Add("Link-Template", `"/inventory/records{/id}{?after,limit,pending}"; rel="`+facts.InventoryRecordsRelation+`"`)
	w.Header().Add("Link-Template", `"/inventory/tokens{?token}"; rel="`+facts.InventoryTokensRelation+`"`)
	w.Header().Add("Link-Template", `"/inventory/audit{?after,limit}"; rel="`+facts.InventoryAuditRelation+`"`)
	w.WriteHeader(204)
}
func inventoryJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func inventoryFailure(w http.ResponseWriter, err error) {
	status := 400
	switch {
	case errors.Is(err, inventory.ErrRevision):
		status = 412
	case errors.Is(err, inventory.ErrConflict):
		status = 409
	case errors.Is(err, inventory.ErrNotFound):
		status = 404
	case errors.Is(err, inventory.ErrToken):
		status = 403
	case errors.Is(err, inventory.ErrStorage):
		status = 503
	}
	var service *facts.ServiceError
	if errors.As(err, &service) {
		status = service.Status
	}
	message := err.Error()
	if status == 503 {
		message = "inventory storage unavailable"
	}
	inventoryJSON(w, status, struct {
		Error string `json:"error"`
	}{message})
}
func writeInventoryRecord(w http.ResponseWriter, status int, h *inventory.HostRecord) {
	w.Header().Set("ETag", facts.InventoryETag(h.Revision))
	w.Header().Set("Location", "/inventory/records/"+url.PathEscape(h.ID))
	inventoryJSON(w, status, h.ControlRecord().InventoryRecord())
}
func (h *inventoryHTTP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxBodySize+1))
	if err != nil || len(body) > wire.MaxBodySize {
		inventoryFailure(w, &facts.ServiceError{Status: 413, Message: "request too large"})
		return
	}
	actor, err := h.verifier.VerifyActor(r, body)
	if err != nil {
		inventoryFailure(w, &facts.ServiceError{Status: 403, Message: "invalid control authentication"})
		return
	}
	// Actor presence is trusted only after signature verification. Enrollment
	// has no actor; a signed administrator may create active patterns only.
	enrollment := r.Method == "POST" && r.URL.Path == "/inventory/records" && actor == ""
	if !enrollment && actor == "" {
		inventoryFailure(w, &facts.ServiceError{Status: 403, Message: "authenticated actor is required"})
		return
	}
	if err = h.execute(w, r, body, actor); err != nil {
		inventoryFailure(w, err)
	}
}
func pageLimit(r *http.Request) (int, error) {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid limit")
	}
	return n, nil
}
func (h *inventoryHTTP) execute(w http.ResponseWriter, r *http.Request, body []byte, actor string) error {
	ctx := r.Context()
	query := r.URL.Query()
	id := r.PathValue("id")
	switch {
	case r.URL.Path == "/inventory/records" && r.Method == "POST":
		var create facts.InventoryCreate
		if err := facts.DecodeInventoryJSON(body, &create); err != nil {
			return err
		}
		if create.Host == nil {
			return fmt.Errorf("host proposal is required")
		}
		p := inventory.ProposalFromControl(create.Host.Proposal())
		var record *inventory.HostRecord
		var err error
		status := 201
		if actor == "" {
			record, err = h.store.Enroll(ctx, p, create.Token)
			if create.Token != "" {
				status = 200
			}
		} else {
			if create.Token != "" {
				return fmt.Errorf("administrator pattern creation cannot use an enrollment token")
			}
			record, err = h.store.AddPattern(ctx, actor, p)
		}
		if err != nil {
			return err
		}
		writeInventoryRecord(w, status, record)
		return nil
	case r.URL.Path == "/inventory/records" && r.Method == "GET":
		limit, err := pageLimit(r)
		if err != nil {
			return err
		}
		pending := false
		if raw := query.Get("pending"); raw != "" {
			pending, err = strconv.ParseBool(raw)
			if err != nil {
				return fmt.Errorf("invalid pending filter")
			}
		}
		records, err := h.store.List(ctx, query.Get("after"), limit, pending)
		if err != nil {
			return err
		}
		result := make([]facts.InventoryRecord, len(records))
		for i, record := range records {
			result[i] = record.ControlRecord().InventoryRecord()
		}
		inventoryJSON(w, 200, result)
		return nil
	case id != "" && r.Method == "GET":
		record, err := h.store.Get(ctx, id)
		if err != nil {
			return err
		}
		writeInventoryRecord(w, 200, record)
		return nil
	case id != "" && (r.Method == "PUT" || r.Method == "DELETE"):
		if r.Header.Get("If-Match") == "" {
			return &facts.ServiceError{Status: 428, Message: "If-Match is required"}
		}
		version, err := facts.InventoryVersion(r.Header.Get("If-Match"))
		if err != nil {
			return err
		}
		if r.Method == "DELETE" {
			if err = h.store.Remove(ctx, actor, id, version); err != nil {
				return err
			}
			w.WriteHeader(204)
			return nil
		}
		var record facts.InventoryRecord
		if err = facts.DecodeInventoryJSON(body, &record); err != nil {
			return err
		}
		// Require the full representation, including explicit null host reservations.
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(body, &fields)
		for _, key := range []string{"id", "status", "host", "createdAt", "updatedAt"} {
			if _, ok := fields[key]; !ok {
				return fmt.Errorf("%s is required", key)
			}
		}
		if record.ID != id {
			return fmt.Errorf("record id must match its URL")
		}
		proposed := inventory.HostRecord{ID: record.ID, Status: record.Status, Proposal: inventory.ProposalFromControl(record.Host.Proposal()), CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}
		result, err := h.store.Replace(ctx, actor, proposed, version)
		if err != nil {
			return err
		}
		writeInventoryRecord(w, 200, result)
		return nil
	case r.URL.Path == "/inventory/tokens" && r.Method == "POST":
		var create facts.InventoryTokenCreate
		if err := facts.DecodeInventoryJSON(body, &create); err != nil {
			return err
		}
		seconds := create.LifetimeSeconds
		if seconds == 0 {
			seconds = 3600
		}
		if seconds < 1 || seconds > 86400 {
			return fmt.Errorf("token lifetime must be between 1s and 24h")
		}
		token, err := h.store.CreateToken(ctx, actor, time.Duration(seconds)*time.Second)
		if err != nil {
			return err
		}
		inventoryJSON(w, 201, facts.InventoryToken{Token: token.ID, ExpiresAt: token.ExpiresAt})
		return nil
	case r.URL.Path == "/inventory/tokens" && r.Method == "DELETE":
		if query.Get("token") == "" {
			return fmt.Errorf("token is required")
		}
		if err := h.store.RevokeToken(ctx, actor, query.Get("token")); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	case r.URL.Path == "/inventory/audit" && r.Method == "GET":
		limit, err := pageLimit(r)
		if err != nil {
			return err
		}
		var after uint64
		if raw := query.Get("after"); raw != "" {
			after, err = strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid audit cursor")
			}
		}
		events, err := h.store.Audit(ctx, inventory.AuditSequence(after), limit)
		if err != nil {
			return err
		}
		result := make([]facts.HostAuditEvent, len(events))
		for i, event := range events {
			result[i] = event.ControlEvent()
		}
		inventoryJSON(w, 200, result)
		return nil
	}
	return &facts.ServiceError{Status: 405, Message: "method not allowed"}
}
