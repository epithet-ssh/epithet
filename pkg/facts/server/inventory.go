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
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// InventoryOption configures optional inventory management.
type InventoryOption func(*inventoryOptions)
type inventoryOptions struct{ managed inventory.Store }

// WithInventoryManagement adds the inventory management API. The data source
// and management implementation must describe the same logical inventory;
// they may be separate instances. The caller owns both lifetimes.
func WithInventoryManagement(managed inventory.Store) InventoryOption {
	return func(options *inventoryOptions) { options.managed = managed }
}

// InventoryHandler serves inventory facts. Management is opt-in, even when hosts
// also implements Store. An empty control key disables management; the CA reader
// key never confers mutation authority. The caller owns the source's lifetime.
func InventoryHandler(hosts inventory.Hosts, caKey, controlKey sshcert.RawPublicKey, options ...InventoryOption) (http.Handler, error) {
	var config inventoryOptions
	for _, option := range options {
		option(&config)
	}
	lookup, err := lookupHandler(nil, hosts, caKey, controlKey)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	if config.managed != nil && controlKey != "" {
		management, err := inventoryHandler(config.managed, controlKey)
		if err != nil {
			return nil, err
		}
		mux.Handle("OPTIONS /lookup", management)
		mux.Handle("/inventory/", management)
	}
	mux.Handle("/lookup", lookup)
	return mux, nil
}

// inventoryHTTP owns the inventory protocol; storage adapters implement complete
// domain operations, with no HTTP, authentication, or JSON knowledge.
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
	w.Header().Add("Link-Template", `"/inventory/audit{?cursor,limit}"; rel="`+facts.InventoryAuditRelation+`"`)
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
	case errors.Is(err, inventory.ErrVersion):
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
func (h *inventoryHTTP) writeInventoryRecord(w http.ResponseWriter, status int, record facts.InventoryRecord, version string) {
	if h.store.SupportsVersioning() && version != "" {
		w.Header().Set("ETag", facts.InventoryETag(version))
	}
	w.Header().Set("Location", "/inventory/records/"+url.PathEscape(record.ID))
	inventoryJSON(w, status, record)
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
	// has no actor; a signed administrator may create active hosts.
	enrollment := r.Method == "PUT" && r.PathValue("id") != "" && actor == ""
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
			return fmt.Errorf("host is required")
		}
		if create.Token != "" {
			return fmt.Errorf("administrator host creation cannot use an enrollment token")
		}
		host := inventoryHost(create.Host)
		host.Status = inventory.StatusActive
		id := inventory.NewID()
		result, err := h.store.CreateHost(ctx, id, host, inventory.NewAuditEvent(actor, "add", id))
		if err != nil {
			return err
		}
		h.writeInventoryRecord(w, 201, hostRecord(result), result.Version)
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
		hosts, err := h.store.ListHosts(ctx, query.Get("after"), limit, pending)
		if err != nil {
			return err
		}
		result := make([]facts.InventoryRecord, 0, len(hosts))
		for i := range hosts {
			result = append(result, hostRecord(&hosts[i]))
		}
		inventoryJSON(w, 200, result)
		return nil
	case id != "" && r.Method == "GET":
		host, err := h.store.GetHost(ctx, id)
		if err != nil {
			return err
		}
		h.writeInventoryRecord(w, 200, hostRecord(host), host.Version)
		return nil
	case id != "" && r.Method == "PUT" && actor == "":
		var submission facts.InventoryCreate
		if err := facts.DecodeInventoryJSON(body, &submission); err != nil {
			return err
		}
		if submission.Host == nil {
			return fmt.Errorf("host is required")
		}
		result, err := inventory.Enroll(ctx, h.store, id, inventoryHost(submission.Host), submission.Token, inventory.NewAuditEvent("host", "enroll", id))
		if err != nil {
			return err
		}
		h.writeInventoryRecord(w, 200, hostRecord(result), result.Version)
		return nil
	case id != "" && (r.Method == "PUT" || r.Method == "DELETE"):
		if h.store.SupportsVersioning() && r.Header.Get("If-Match") == "" {
			return &facts.ServiceError{Status: 428, Message: "If-Match is required"}
		}
		expectedVersion, err := facts.InventoryVersion(r.Header.Get("If-Match"))
		if err != nil {
			return err
		}
		if !h.store.SupportsVersioning() && expectedVersion != "" {
			return inventory.ErrVersion
		}
		if r.Method == "DELETE" {
			event := inventory.NewAuditEvent(actor, "remove", id)
			err = h.store.RemoveHost(ctx, id, expectedVersion, event)
			if err != nil {
				return err
			}
			w.WriteHeader(204)
			return nil
		}
		var record facts.InventoryRecord
		if err = facts.DecodeInventoryJSON(body, &record); err != nil {
			return err
		}
		// Require the full representation.
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
		current, err := h.store.GetHost(ctx, id)
		if err != nil {
			return err
		}
		proposed := inventoryHost(record.Host)
		proposed.ID, proposed.Status, proposed.CreatedAt, proposed.UpdatedAt = record.ID, record.Status, record.CreatedAt, record.UpdatedAt
		event := inventory.NewAuditEvent(actor, "", id)
		_, action, err := inventory.Review(*current, proposed, expectedVersion, event.At)
		if err != nil {
			return err
		}
		event.Action = action
		result, err := h.store.ReplaceHost(ctx, proposed, expectedVersion, event)
		if err != nil {
			return err
		}
		h.writeInventoryRecord(w, 200, hostRecord(result), result.Version)
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
		id := inventory.NewID()
		token, err := h.store.CreateToken(ctx, id, time.Duration(seconds)*time.Second, inventory.NewAuditEvent(actor, "token-create", id))
		if err != nil {
			return err
		}
		inventoryJSON(w, 201, facts.InventoryToken{Token: token.ID, ExpiresAt: token.ExpiresAt})
		return nil
	case r.URL.Path == "/inventory/tokens" && r.Method == "DELETE":
		if query.Get("token") == "" {
			return fmt.Errorf("token is required")
		}
		if err := h.store.RevokeToken(ctx, query.Get("token"), inventory.NewAuditEvent(actor, "token-revoke", query.Get("token"))); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	case r.URL.Path == "/inventory/audit" && r.Method == "GET":
		limit, err := pageLimit(r)
		if err != nil {
			return err
		}
		events, next, err := h.store.Audit(ctx, query.Get("cursor"), limit)
		if err != nil {
			return err
		}
		result := make([]facts.HostAuditEvent, len(events))
		for i, event := range events {
			result[i] = facts.HostAuditEvent{At: event.At, Actor: event.Actor, Action: event.Action, Resource: event.Resource}
		}
		inventoryJSON(w, 200, facts.AuditPage[facts.HostAuditEvent]{Events: result, Next: next})
		return nil
	}
	return &facts.ServiceError{Status: 405, Message: "method not allowed"}
}

// The HTTP document keeps lifecycle metadata separate from editable host facts.
func hostRecord(h *inventory.Host) facts.InventoryRecord {
	fields := &facts.InventoryHost{Name: h.Names, Attributes: h.Labels, Accounts: h.Accounts, Principal: facts.InventoryPrincipal{Mode: string(h.PrincipalMode), Realm: string(h.Realm)}}
	return facts.InventoryRecord{ID: h.ID, Status: h.Status, CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt, Host: fields}
}
func inventoryHost(p *facts.InventoryHost) inventory.Host {
	if p == nil {
		return inventory.Host{}
	}
	return inventory.Host{Names: p.Name, Labels: p.Attributes, Accounts: p.Accounts, PrincipalMode: inventory.PrincipalMode(p.Principal.Mode), Realm: principal.Realm(p.Principal.Realm)}
}
