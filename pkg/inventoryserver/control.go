package inventoryserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

type TokenValidator interface {
	Validate(context.Context, string) (*oidc.Claims, error)
}

// Admins is intentionally one role. IDs use the same configured claim mapping
// and active directory records as certificate issuance, never a second identity.
type Admins struct {
	Users  []string
	Groups []string
}

func (a Admins) Allows(u *directory.User) bool {
	if u == nil || !u.Active {
		return false
	}
	if slices.Contains(a.Users, u.ID) {
		return true
	}
	for _, g := range u.Groups {
		if slices.Contains(a.Groups, g) {
			return true
		}
	}
	return false
}

type Control struct {
	Store     *inventory.Managed
	Directory directory.Directory
	Validator TokenValidator
	Admins    Admins
	// Bound anonymous enrollment to a small global burst and sustained rate.
	mu        sync.Mutex
	allowance float64
	last      time.Time
}

func (c *Control) admit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.last.IsZero() {
		c.allowance = 20
	} else {
		c.allowance = min(20, c.allowance+now.Sub(c.last).Seconds())
	}
	c.last = now
	if c.allowance < 1 {
		return false
	}
	c.allowance--
	return true
}
func (c *Control) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(inventoryapi.ControlResponse{Error: msg})
	}
	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(map[string]any{"version": 1, "capabilities": []string{"enroll", "admin"}})
		return
	}
	if r.Method != http.MethodPost {
		fail(405, "method not allowed")
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxBodySize+1))
	if err != nil || len(body) > wire.MaxBodySize {
		fail(413, "request too large")
		return
	}
	var req inventoryapi.ControlRequest
	d := json.NewDecoder(strings.NewReader(string(body)))
	d.DisallowUnknownFields()
	if err = d.Decode(&req); err != nil {
		fail(400, "invalid inventory request")
		return
	}
	if d.Decode(new(any)) != io.EOF {
		fail(400, "invalid inventory request")
		return
	}
	actor := ""
	if req.Action == "enroll" {
		if !c.admit() {
			fail(429, "enrollment rate limit; retry later")
			return
		}
	} else {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			fail(401, "authentication required")
			return
		}
		claims, e := c.Validator.Validate(r.Context(), raw)
		if e != nil {
			fail(401, "invalid or expired authentication")
			return
		}
		u, e := c.Directory.LookupUser(r.Context(), claims.UserID)
		if e != nil {
			fail(503, "directory unavailable")
			return
		}
		if !c.Admins.Allows(u) {
			fail(403, "inventory-admin role required")
			return
		}
		actor = u.ID
	}
	if (req.Action == "edit" || req.Action == "enroll") && req.Host != nil {
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(body, &raw)
		var host map[string]json.RawMessage
		_ = json.Unmarshal(raw["host"], &host)
		if _, ok := host["accounts"]; !ok {
			fail(400, "accounts must be explicit")
			return
		}
	}
	var resp inventoryapi.ControlResponse
	switch req.Action {
	case "enroll":
		if req.Host == nil {
			err = fmt.Errorf("host proposal is required")
			break
		}

		resp.Host, err = c.Store.Enroll(*req.Host, req.Token)
	case "list":
		resp.Hosts, err = c.Store.List()
	case "get":
		resp.Host, err = c.Store.Get(req.ID)
	case "edit", "approve", "deny", "remove":
		resp.Host, err = c.Store.Change(actor, req.Action, req.ID, req.Revision, req.Host)
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
		t, resp.Secret, err = c.Store.CreateToken(actor, time.Duration(seconds)*time.Second)
		resp.Token = &t
	case "token-list":
		resp.Tokens, err = c.Store.Tokens()
	case "token-revoke":
		err = c.Store.RevokeToken(actor, req.ID)
	case "audit":
		resp.Audit, err = c.Store.Audit()
	default:
		err = fmt.Errorf("unknown inventory action")
	}
	if err != nil {
		code := 400
		switch {
		case errors.Is(err, inventory.ErrConflict), errors.Is(err, inventory.ErrRevision):
			code = 409
		case errors.Is(err, inventory.ErrNotFound):
			code = 404
		case errors.Is(err, inventory.ErrToken):
			code = 403
		case errors.Is(err, inventory.ErrStorage):
			code = 503
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
