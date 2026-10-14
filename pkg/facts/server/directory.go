// Package server serves built-in directory and inventory facts and their private
// management APIs. It authenticates service keys; public user authentication and
// administrative authorization belong to the control plane. Stores retain
// ownership of mutation invariants, transactions, and audit records.
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/scim"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
)

// DirectoryOption configures optional directory management.
type DirectoryOption func(*directoryOptions)
type directoryOptions struct {
	managed         directory.Store
	userIDAttribute string
}

// WithDirectoryManagement adds SCIM and managed directory operations. The data
// source and management implementation must describe the same logical directory;
// they may be separate instances. The caller owns both lifetimes.
func WithDirectoryManagement(managed directory.Store) DirectoryOption {
	return func(options *directoryOptions) { options.managed = managed }
}

// WithSCIMUserIDAttribute selects the SCIM string attribute used to assign a
// user's ID on creation. The default is externalId. This configures the SCIM
// adapter, not the store, and requires directory management to be enabled.
func WithSCIMUserIDAttribute(attribute string) DirectoryOption {
	return func(options *directoryOptions) { options.userIDAttribute = attribute }
}

// DirectoryHandler serves directory facts and the read-only actor operation.
// Management is opt-in, even when users also implements Store. An empty control key disables all private control routes.
func DirectoryHandler(users directory.Directory, caKey, controlKey sshcert.RawPublicKey, options ...DirectoryOption) (http.Handler, error) {
	var config directoryOptions
	for _, option := range options {
		option(&config)
	}
	if config.userIDAttribute != "" && config.managed == nil {
		return nil, fmt.Errorf("SCIM user ID attribute requires directory management")
	}
	lookup, err := lookupHandler(users, nil, caKey, controlKey)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/lookup", lookup)
	if controlKey != "" {
		management := &directoryHTTP{Directory: users, ManagedDirectory: config.managed, UserIDAttribute: config.userIDAttribute}
		handler, err := management.handler(controlKey)
		if err != nil {
			return nil, err
		}
		for _, path := range []string{"/manage", "/actor", "/scim/v2/", "OPTIONS /lookup"} {
			mux.Handle(path, handler)
		}
	}
	return mux, nil
}

// directoryHTTP adapts the private control protocol to store operations. Only the
// configured control key can invoke it; CA reader credentials never confer
// mutation authority. Stores enforce their transactional invariants.
type directoryHTTP struct {
	ManagedDirectory directory.Store
	Directory        directory.Directory
	UserIDAttribute  string
}

func (c *directoryHTTP) handler(key sshcert.RawPublicKey) (http.Handler, error) {
	verifier, err := serviceauth.NewVerifierFor(key, serviceauth.DirectoryAudience)
	if err != nil {
		return nil, err
	}
	var provision http.Handler
	if c.ManagedDirectory != nil {
		provision, err = scim.NewBackend(c.ManagedDirectory, c.UserIDAttribute)
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
		if strings.HasPrefix(r.URL.Path, "/scim/v2/") {
			if provision == nil {
				http.NotFound(w, r)
				return
			}
			if actor == "" {
				http.Error(w, "authenticated actor is required", 403)
				return
			}
			r = r.WithContext(directory.WithActor(r.Context(), actor))
			r.Body = io.NopCloser(bytes.NewReader(body))
			provision.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case "/actor":
			if r.Method != "GET" || c.Directory == nil || r.URL.Query().Get("id") == "" {
				http.NotFound(w, r)
				return
			}
			u, err := c.Directory.LookupUser(r.Context(), r.URL.Query().Get("id"))
			if err != nil {
				http.Error(w, "directory unavailable", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(facts.ActorSnapshot{User: controlActor(u)})
		case "/lookup":
			if r.Method != "OPTIONS" || provision == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Allow", "GET, OPTIONS")
			w.Header().Set("Link", `</scim/v2/>; rel="`+wire.RelSCIM+`"`)
			w.WriteHeader(http.StatusNoContent)
		case "/manage":
			c.manage(w, r, body, actor)
		default:
			http.NotFound(w, r)
		}
	}), nil
}
func (c *directoryHTTP) manage(w http.ResponseWriter, r *http.Request, body []byte, actor string) {
	w.Header().Set("Content-Type", "application/json")
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(facts.ControlResponse{Error: msg})
	}
	if r.Method == "GET" {
		capabilities := []string{"admin"}
		if c.ManagedDirectory != nil {
			capabilities = append(capabilities, "directory")
		}
		json.NewEncoder(w).Encode(facts.Capabilities{Version: 1, Capabilities: capabilities})
		return
	}
	if r.Method != "POST" {
		fail(405, "method not allowed")
		return
	}
	var envelope facts.ControlEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		fail(400, "invalid control request")
		return
	}
	req := envelope.Request
	isDirectory := req.Action == "directory-audit"
	if c.ManagedDirectory == nil || !isDirectory {
		fail(404, "requested inventory capability is not configured")
		return
	}
	if actor == "" {
		fail(403, "authenticated actor is required")
		return
	}
	var err error
	var resp facts.ControlResponse
	switch req.Action {
	case "directory-audit":
		var events []directory.AuditEvent
		var next string
		events, next, err = c.ManagedDirectory.Audit(r.Context(), req.AuditCursor, req.AuditLimit)
		resp.DirectoryAudit = &facts.AuditPage[facts.DirectoryAuditEvent]{Events: controlSlice(events, controlDirectoryEvent), Next: next}
	default:
		err = fmt.Errorf("unknown inventory action")
	}
	if err != nil {
		code := 400
		switch {
		case errors.Is(err, directory.ErrConflict), errors.Is(err, directory.ErrVersion):
			code = 409
		case errors.Is(err, directory.ErrNotFound):
			code = 404
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
	json.NewEncoder(w).Encode(resp)
}

// Directory projections stay here so storage never learns the control protocol.

// controlSlice maps a slice element-wise, preserving nil versus empty.
func controlSlice[S, T any](in []S, f func(S) T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	for i, s := range in {
		out[i] = f(s)
	}
	return out
}

func controlDirectoryEvent(e directory.AuditEvent) facts.DirectoryAuditEvent {
	return facts.DirectoryAuditEvent{
		Time:       e.Time,
		Actor:      e.Actor,
		Action:     e.Action,
		ID:         e.ID,
		Alias:      e.Alias,
		PreviousID: e.PreviousID,
	}
}

func controlActor(u *directory.User) *facts.Actor {
	if u == nil {
		return nil
	}
	return &facts.Actor{UserName: u.UserName, ID: u.ID, Active: u.Active, Groups: object.GroupNames(u.Facts().Groups), UserType: u.UserType, Department: u.Department, Organization: u.Organization}
}
