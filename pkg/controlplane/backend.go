// Package controlplane separates public authentication from backend mutations.
package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/directory/scim"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// Backend owns only storage and invariants. Only the configured control key can
// invoke it; CA reader credentials never confer mutation authority.
type Backend struct {
	Store            *inventory.Managed
	ManagedDirectory directory.Store
	Directory        directory.Directory
}
type request struct {
	Request               inventoryapi.ControlRequest `json:"request"`
	AuthorizationRevision directory.Revision          `json:"authorizationRevision,omitempty"`
}
type actorFacts struct {
	User     *directory.User    `json:"user"`
	Revision directory.Revision `json:"authorizationRevision"`
}
type scimRequest struct {
	Method      string `json:"method"`
	Target      string `json:"target"`
	ContentType string `json:"contentType"`
	IfMatch     string `json:"ifMatch"`
	Body        []byte `json:"body"`
}

func (c *Backend) Handler(key sshcert.RawPublicKey) (http.Handler, error) {
	audience := serviceauth.InventoryAudience
	if c.Directory != nil {
		audience = serviceauth.DirectoryAudience
	}
	verifier, err := serviceauth.NewVerifierFor(key, audience)
	if err != nil {
		return nil, err
	}
	var provision http.Handler
	if c.ManagedDirectory != nil {
		provision, err = scim.NewBackend(c.ManagedDirectory)
		if err != nil {
			return nil, err
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20+1))
		if err != nil || len(body) > 8<<20 {
			http.Error(w, "request too large", 413)
			return
		}
		actor, err := verifier.VerifyActor(r, body)
		if err != nil {
			http.Error(w, "invalid control authentication", 403)
			return
		}
		switch r.URL.Path {
		case "/actor":
			if r.Method != "GET" || c.Directory == nil || r.URL.Query().Get("id") == "" {
				http.NotFound(w, r)
				return
			}
			u, rev, err := c.Directory.LookupUser(r.Context(), r.URL.Query().Get("id"))
			if err != nil {
				http.Error(w, "directory unavailable", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(actorFacts{u, rev})
		case "/scim":
			if r.Method != "POST" || provision == nil || actor != "" {
				http.NotFound(w, r)
				return
			}
			var q scimRequest
			if err := json.Unmarshal(body, &q); err != nil || !strings.HasPrefix(q.Target, "/scim/v2/") {
				http.Error(w, "invalid SCIM request", 400)
				return
			}
			inner, err := http.NewRequestWithContext(r.Context(), q.Method, q.Target, bytes.NewReader(q.Body))
			if err != nil {
				http.Error(w, "invalid SCIM request", 400)
				return
			}
			inner.Header.Set("Content-Type", q.ContentType)
			inner.Header.Set("If-Match", q.IfMatch)
			provision.ServeHTTP(w, inner)
		case "/manage":
			c.manage(w, r, body, actor)
		default:
			http.NotFound(w, r)
		}
	}), nil
}
func (c *Backend) manage(w http.ResponseWriter, r *http.Request, body []byte, actor string) {
	users, canListUsers := c.Directory.(directory.UserLister)
	w.Header().Set("Content-Type", "application/json")
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(inventoryapi.ControlResponse{Error: msg})
	}
	if r.Method == "GET" {
		capabilities := []string{"admin"}
		if c.Store != nil {
			capabilities = append(capabilities, "enroll")
		}
		if c.ManagedDirectory != nil {
			capabilities = append(capabilities, "directory")
		}
		if canListUsers {
			capabilities = append(capabilities, "directory-users")
		}
		json.NewEncoder(w).Encode(inventoryapi.Capabilities{Version: 1, Capabilities: capabilities})
		return
	}
	if r.Method != "POST" {
		fail(405, "method not allowed")
		return
	}
	var envelope request
	if err := json.Unmarshal(body, &envelope); err != nil {
		fail(400, "invalid control request")
		return
	}
	req, authorizationRevision := envelope.Request, envelope.AuthorizationRevision
	isUserList := req.Action == "directory-users"
	isManagedDirectory := req.Action == "directory-groups" || req.Action == "directory-bind" || req.Action == "directory-audit"
	isDirectory := isUserList || isManagedDirectory
	if isUserList && !canListUsers || isManagedDirectory && c.ManagedDirectory == nil || !isDirectory && c.Store == nil {
		fail(404, "requested inventory capability is not configured")
		return
	}
	if req.Action != "enroll" && actor == "" {
		fail(403, "authenticated actor is required")
		return
	}
	if req.Action == "enroll" && actor != "" {
		fail(400, "enrollment is not a human administrative operation")
		return
	}
	var err error
	var resp inventoryapi.ControlResponse
	switch req.Action {
	case "directory-users":
		var facts []directory.User
		var revision directory.Revision
		facts, revision, err = users.ListUserFacts(r.Context())
		resp.DirectoryUsers = &inventoryapi.UserSnapshot{Revision: string(revision), Users: controlSlice(facts, controlUser)}
	case "directory-groups":
		var snapshot directory.BindingSnapshot
		snapshot, err = c.ManagedDirectory.Bindings(r.Context())
		resp.Directory = controlBindings(snapshot)
	case "directory-bind":
		err = c.ManagedDirectory.Rebind(r.Context(), actor, req.Alias, req.ID, req.Revision, authorizationRevision)
	case "directory-audit":
		var events []directory.AuditEvent
		events, err = c.ManagedDirectory.Audit(r.Context(), directory.AuditSequence(req.AuditAfter), req.AuditLimit)
		resp.DirectoryAudit = controlSlice(events, controlDirectoryEvent)
	case "enroll":
		if req.Host == nil {
			err = fmt.Errorf("host proposal is required")
			break
		}
		var h *inventory.HostRecord
		h, err = c.Store.Enroll(inventory.ProposalFromControl(*req.Host), req.Token)
		resp.Host = controlRecord(h)
	case "list":
		var hosts []inventory.HostRecord
		hosts, err = c.Store.List()
		resp.Hosts = controlSlice(hosts, inventory.HostRecord.ControlRecord)
	case "get":
		var h *inventory.HostRecord
		h, err = c.Store.Get(req.ID)
		resp.Host = controlRecord(h)
	case "edit", "approve", "deny", "remove":
		var proposal *inventory.Proposal
		if req.Host != nil {
			p := inventory.ProposalFromControl(*req.Host)
			proposal = &p
		}
		var h *inventory.HostRecord
		h, err = c.Store.Change(actor, req.Action, req.ID, req.Revision, proposal)
		resp.Host = controlRecord(h)
	case "token-create":
		seconds := req.LifetimeSeconds
		if seconds == 0 {
			seconds = 3600
		}
		if seconds < 1 || seconds > 86400 {
			err = fmt.Errorf("token lifetime must be between 1s and 24h")
			break
		}
		var t inventory.EnrollmentToken
		t, err = c.Store.CreateToken(actor, time.Duration(seconds)*time.Second)
		token := t.ControlToken()
		resp.Token = &token
	case "token-list":
		var tokens []inventory.EnrollmentToken
		tokens, err = c.Store.Tokens()
		resp.Tokens = controlSlice(tokens, inventory.EnrollmentToken.ControlToken)
	case "token-revoke":
		err = c.Store.RevokeToken(actor, req.ID)
	case "audit":
		var events []inventory.AuditEvent
		events, err = c.Store.Audit()
		resp.Audit = controlSlice(events, inventory.AuditEvent.ControlEvent)
	default:
		err = fmt.Errorf("unknown inventory action")
	}
	if err != nil {
		code := 400
		switch {
		case errors.Is(err, inventory.ErrConflict), errors.Is(err, inventory.ErrRevision), errors.Is(err, directory.ErrConflict), errors.Is(err, directory.ErrVersion):
			code = 409
		case errors.Is(err, inventory.ErrNotFound), errors.Is(err, directory.ErrNotFound):
			code = 404
		case errors.Is(err, inventory.ErrToken):
			code = 403
		case errors.Is(err, inventory.ErrStorage):
			code = 503
		default:
			if isDirectory && !errors.Is(err, directory.ErrInvalid) {
				code = 503
			}
		}
		if code == 503 {
			fail(code, "inventory storage unavailable")
		} else {
			fail(code, err.Error())
		}
		return
	}
	if req.Action == "enroll" && resp.Host.Status == "pending" {
		w.WriteHeader(http.StatusAccepted)
	}
	json.NewEncoder(w).Encode(resp)
}
