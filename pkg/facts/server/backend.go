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
)

// backend adapts the private control protocol to store operations. Only the
// configured control key can invoke it; CA reader credentials never confer
// mutation authority. Stores enforce their transactional invariants.
type backend struct {
	ManagedDirectory directory.Store
	Directory        directory.Directory
}

func (c *backend) handler(key sshcert.RawPublicKey) (http.Handler, error) {
	verifier, err := serviceauth.NewVerifierFor(key, serviceauth.DirectoryAudience)
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
			u, rev, err := c.Directory.LookupUser(r.Context(), r.URL.Query().Get("id"))
			if err != nil {
				http.Error(w, "directory unavailable", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(facts.ActorSnapshot{User: controlActor(u), Revision: string(rev)})
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
func (c *backend) manage(w http.ResponseWriter, r *http.Request, body []byte, actor string) {
	users, canListUsers := c.Directory.(directory.UserLister)
	if c.ManagedDirectory != nil {
		users, canListUsers = c.ManagedDirectory, true
	}
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
		if canListUsers {
			capabilities = append(capabilities, "directory-users")
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
	isUserList := req.Action == "directory-users"
	isManagedDirectory := req.Action == "directory-groups" || req.Action == "directory-audit"
	isDirectory := isUserList || isManagedDirectory
	if isUserList && !canListUsers || isManagedDirectory && c.ManagedDirectory == nil || !isDirectory {
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
	case "directory-users":
		var userFacts []directory.User
		var revision directory.Revision
		userFacts, revision, err = users.ListUserFacts(r.Context())
		resp.DirectoryUsers = &facts.UserSnapshot{Revision: string(revision), Users: controlSlice(userFacts, controlUser)}
	case "directory-groups":
		var snapshot directory.GroupSnapshot
		snapshot, err = c.ManagedDirectory.Groups(r.Context())
		resp.Directory = controlGroups(snapshot)
	case "directory-audit":
		var events []directory.AuditEvent
		events, err = c.ManagedDirectory.Audit(r.Context(), directory.AuditSequence(req.AuditAfter), req.AuditLimit)
		resp.DirectoryAudit = controlSlice(events, controlDirectoryEvent)
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
