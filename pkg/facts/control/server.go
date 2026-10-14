// Package control authenticates public requests and authorizes administrative
// operations, then invokes fact services through their typed clients. Built-in
// private service handlers and storage adapters live in pkg/facts/server.
package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
)

type TokenValidator interface {
	Validate(context.Context, string) (*oidc.Claims, error)
}
type Admins struct{ Users, Groups []string }

func (a Admins) Allows(u *facts.Actor) bool {
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

// Config keeps identity and administrative grants at control. The directory
// complete lookup URL is required and discovers optional SCIM management.
// DirectoryBackendURL enables the built-in directory snapshot and audit APIs;
// InventoryBackendURL is the complete inventory fact endpoint where optional
// management resources are discovered.
type Config struct {
	Key                                                    sshcert.RawPrivateKey
	DirectoryURL, DirectoryBackendURL, InventoryBackendURL string
	Validator                                              TokenValidator
	DirectoryAdmins, InventoryAdmins                       Admins
	SCIMToken                                              string
	InventoryToken                                         string
	TLS                                                    tlsconfig.Config
}
type Server struct {
	config    Config
	data      *facts.DataClient
	control   *facts.ControlClient
	directory *servicehttp.Client
	mu        sync.Mutex
	allowance float64
	last      time.Time
}

func New(config Config) (*Server, error) {
	if config.Validator == nil {
		return nil, fmt.Errorf("control OIDC validator is required")
	}
	data, err := facts.NewDataClient(config.DirectoryURL, "", config.Key, config.TLS)
	if err != nil {
		return nil, err
	}
	control, err := facts.NewControlClient(config.DirectoryBackendURL, config.InventoryBackendURL, config.Key, config.TLS)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(config.SCIMToken, " \t\r\n") {
		return nil, fmt.Errorf("SCIM requires a bearer token without whitespace")
	}
	if config.InventoryToken != "" && (config.InventoryBackendURL == "" || strings.ContainsAny(config.InventoryToken, " \t\r\n")) {
		return nil, fmt.Errorf("inventory token requires an inventory fact endpoint and no whitespace")
	}
	directory, err := servicehttp.New(config.DirectoryURL, "/lookup", config.Key, serviceauth.DirectoryAudience, config.TLS)
	if err != nil {
		return nil, err
	}
	s := &Server{config: config, data: data, control: control, directory: directory}
	return s, nil
}
func (s *Server) admit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.last.IsZero() {
		s.allowance = 20
	} else {
		s.allowance = min(20, s.allowance+now.Sub(s.last).Seconds())
	}
	s.last = now
	if s.allowance < 1 {
		return false
	}
	s.allowance--
	return true
}
func controlError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(facts.ControlResponse{Error: message})
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(r.URL.Path, "/scim/v2/") {
		s.scim(w, r)
		return
	}
	if r.URL.Path != "/manage" {
		http.NotFound(w, r)
		return
	}
	if r.Method == "GET" {
		s.capabilities(w, r)
		return
	}
	if r.Method != "POST" {
		controlError(w, 405, "method not allowed")
		return
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxBodySize+1))
	if err != nil || len(data) > wire.MaxBodySize {
		controlError(w, 413, "request too large")
		return
	}
	var req facts.ControlRequest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		controlError(w, 400, "invalid inventory request")
		return
	}
	if dec.Decode(new(any)) != io.EOF {
		controlError(w, 400, "invalid inventory request")
		return
	}
	isDirectory := strings.HasPrefix(req.Action, "directory-")
	endpoint, admins := s.config.InventoryBackendURL, s.config.InventoryAdmins
	role := "inventory-admin"
	if isDirectory {
		endpoint, admins = s.config.DirectoryBackendURL, s.config.DirectoryAdmins
		role = "directory-admin"
	}
	if endpoint == "" {
		controlError(w, 404, "requested inventory capability is not configured")
		return
	}
	actor, revision := "", ""
	if req.Action == "enroll" {
		if !s.admit() {
			controlError(w, 429, "enrollment rate limit; retry later")
			return
		}
	} else {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			controlError(w, 401, "authentication required")
			return
		}
		if !isDirectory && matchesSecret(raw, s.config.InventoryToken) {
			actor = "inventory-token"
		} else {
			auth, rejected := s.authorizeAdmin(r.Context(), raw, admins, role)
			if rejected != nil {
				controlError(w, rejected.Status, rejected.Message)
				return
			}
			actor, revision = auth.Actor, auth.DirectoryRevision
		}
	}
	result, err := s.execute(r.Context(), req, facts.Authorization{Actor: actor, DirectoryRevision: revision})
	if err != nil {
		var rejected *facts.ServiceError
		if errors.As(err, &rejected) {
			controlError(w, rejected.Status, rejected.Message)
		} else {
			controlError(w, 503, "control backend unavailable")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if req.Action == "enroll" && result.Host.Status == "pending" {
		w.WriteHeader(http.StatusAccepted)
	}
	json.NewEncoder(w).Encode(result)
}

// execute adapts the public operation envelope to the typed private client.
// Authentication and role checks precede this dispatch; the client owns the
// signed backend protocol and returns only domain results.
func (s *Server) execute(ctx context.Context, req facts.ControlRequest, auth facts.Authorization) (*facts.ControlResponse, error) {
	var result facts.ControlResponse
	var err error
	invalid := func(message string) (*facts.ControlResponse, error) {
		return nil, &facts.ServiceError{Status: 400, Message: message}
	}
	switch req.Action {
	case "enroll":
		if req.Host == nil {
			return invalid("host proposal is required")
		}
		result.Host, err = s.control.Enroll(ctx, *req.Host, req.Token)
	case "add-pattern":
		if req.Host == nil {
			return invalid("pattern proposal is required")
		}
		result.Host, err = s.control.AddPattern(ctx, auth, *req.Host)
	case "list":
		result.Hosts, err = s.control.Hosts(ctx, auth, req.After, req.Limit, req.Pending)
	case "get":
		result.Host, err = s.control.Host(ctx, auth, req.ID)
	case "edit":
		if req.Host == nil {
			return invalid("host proposal is required")
		}
		result.Host, err = s.control.EditHost(ctx, auth, req.ID, req.Revision, *req.Host)
	case "approve":
		result.Host, err = s.control.ApproveHost(ctx, auth, req.ID, req.Revision)
	case "deny":
		result.Host, err = s.control.DenyHost(ctx, auth, req.ID, req.Revision)
	case "remove":
		err = s.control.RemoveHost(ctx, auth, req.ID, req.Revision)
	case "token-create":
		result.Token, err = s.control.CreateToken(ctx, auth, req.LifetimeSeconds)
	case "token-revoke":
		err = s.control.RevokeToken(ctx, auth, req.ID)
	case "audit":
		result.Audit, err = s.control.HostAudit(ctx, auth, req.AuditAfter, req.AuditLimit)
	case "directory-users":
		result.DirectoryUsers, err = s.control.Users(ctx, auth)
	case "directory-groups":
		result.Directory, err = s.control.Groups(ctx, auth)
	case "directory-audit":
		result.DirectoryAudit, err = s.control.DirectoryAudit(ctx, auth, req.AuditAfter, req.AuditLimit)
	default:
		return invalid("unknown inventory action")
	}
	return &result, err
}
func (s *Server) actor(ctx context.Context, id string) (*facts.Actor, string, error) {
	if s.config.DirectoryBackendURL != "" {
		return s.control.Actor(ctx, id)
	}
	u, err := s.data.User(ctx, id)
	if err != nil || u == nil {
		return nil, "", err
	}
	return &facts.Actor{ID: u.ID, UserName: u.UserName, Active: true, Groups: object.GroupNames(u.Groups)}, "", nil
}
func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	result, err := s.control.Capabilities(r.Context())
	if err != nil {
		controlError(w, 503, "control backend unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Hash both inputs so comparison time does not disclose credential length.
func matchesSecret(actual, expected string) bool {
	if actual == "" || expected == "" {
		return false
	}
	a, b := sha256.Sum256([]byte(actual)), sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// authorizeAdmin is shared by SCIM and command administration: public identity
// validation and active-user grants have one owner, before provider dispatch.
func (s *Server) authorizeAdmin(ctx context.Context, token string, admins Admins, role string) (facts.Authorization, *facts.ServiceError) {
	fail := func(status int, message string) (facts.Authorization, *facts.ServiceError) {
		return facts.Authorization{}, &facts.ServiceError{Status: status, Message: message}
	}
	if token == "" {
		return fail(401, "authentication required")
	}
	claims, err := s.config.Validator.Validate(ctx, token)
	if err != nil {
		if errors.Is(err, oidc.ErrUnavailable) {
			return fail(503, "OIDC dependency unavailable")
		}
		return fail(401, "invalid or expired authentication")
	}
	u, revision, err := s.actor(ctx, claims.UserID)
	if err != nil {
		return fail(503, "directory unavailable")
	}
	if !admins.Allows(u) {
		return fail(403, role+" role required")
	}
	return facts.Authorization{Actor: u.ID, DirectoryRevision: revision}, nil
}
