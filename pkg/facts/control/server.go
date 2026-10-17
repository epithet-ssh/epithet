// Package control authenticates public requests and authorizes administrative
// operations, then invokes the private provider protocols. Built-in
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

// authorization is the identity already authorized by public control.
// The actor is signed in the service credential. Provider calls do not grant roles.
type authorization struct {
	Actor string
}

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
	// EnrollmentToken authorizes pending submissions only. Empty disables that
	// path; single-use preapproval credentials are validated by inventory.
	EnrollmentToken string
	TLS             tlsconfig.Config
}
type Server struct {
	config           Config
	data             *facts.DataClient
	directoryBackend *servicehttp.Client
	inventory        *servicehttp.Client
	directory        *servicehttp.Client
	mu               sync.Mutex
	allowance        float64
	last             time.Time
}

func New(config Config) (*Server, error) {
	if config.Validator == nil {
		return nil, fmt.Errorf("control OIDC validator is required")
	}
	data, err := facts.NewDataClient(config.DirectoryURL, "", config.Key, config.TLS)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(config.SCIMToken, " \t\r\n") {
		return nil, fmt.Errorf("SCIM requires a bearer token without whitespace")
	}
	if config.InventoryToken != "" && (config.InventoryBackendURL == "" || strings.ContainsAny(config.InventoryToken, " \t\r\n")) {
		return nil, fmt.Errorf("inventory token requires an inventory fact endpoint and no whitespace")
	}
	if config.EnrollmentToken != "" && (config.InventoryBackendURL == "" || strings.ContainsAny(config.EnrollmentToken, " \t\r\n")) {
		return nil, fmt.Errorf("enrollment token requires an inventory fact endpoint and no whitespace")
	}
	directory, err := servicehttp.New(config.DirectoryURL, "/lookup", config.Key, serviceauth.DirectoryAudience, config.TLS)
	if err != nil {
		return nil, err
	}
	s := &Server{config: config, data: data, directory: directory}
	if config.DirectoryBackendURL != "" {
		s.directoryBackend, err = servicehttp.New(config.DirectoryBackendURL, "", config.Key, serviceauth.DirectoryAudience, config.TLS)
		if err != nil {
			return nil, err
		}
	}
	if config.InventoryBackendURL != "" {
		s.inventory, err = servicehttp.New(config.InventoryBackendURL, "/lookup", config.Key, serviceauth.InventoryAudience, config.TLS)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// providerCapabilities combines the enabled backends' supported operations. Failure to
// read a backend is an error, never evidence that its capabilities are absent.
func (c *Server) providerCapabilities(ctx context.Context) (facts.Capabilities, error) {
	result := facts.Capabilities{Version: 1, Capabilities: []string{"admin"}}
	if c.directoryBackend != nil {
		resp, err := directoryRequest(ctx, c.directoryBackend, "GET", "/manage", nil, nil, "", 65536)
		if err != nil {
			return result, err
		}
		var caps facts.Capabilities
		if err = decodeControl(resp, &caps); err != nil {
			return result, err
		}
		if caps.Version != 1 || caps.Capabilities == nil {
			return result, fmt.Errorf("%w: invalid backend capabilities", facts.ErrUnavailable)
		}
		for _, cap := range caps.Capabilities {
			if !slices.Contains(result.Capabilities, cap) {
				result.Capabilities = append(result.Capabilities, cap)
			}
		}
	}
	templates, err := c.inventoryTemplates(ctx)
	if err != nil {
		return result, err
	}
	if len(templates) != 0 {
		result.Capabilities = append(result.Capabilities, "enroll")
	}
	return result, nil
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
	enrollmentPath := strings.HasPrefix(r.URL.Path, "/manage/")
	if r.URL.Path != "/manage" && !enrollmentPath {
		http.NotFound(w, r)
		return
	}
	if !enrollmentPath && r.Method == "GET" {
		s.capabilities(w, r)
		return
	}
	if (enrollmentPath && r.Method != "PUT") || (!enrollmentPath && r.Method != "POST") {
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
	if (req.Action == "enroll") != enrollmentPath {
		controlError(w, 405, "enrollment requires PUT to the host id")
		return
	}
	if enrollmentPath {
		id := strings.TrimPrefix(r.URL.Path, "/manage/")
		if id == "" || strings.Contains(id, "/") || req.ID != id || (req.Token != "" && req.Token != id) {
			controlError(w, 400, "enrollment id must match its URL and token")
			return
		}
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
	actor := ""
	if req.Action == "enroll" {
		// A single-use credential authorizes activation at the provider. Without
		// one, require the shared credential before forwarding a pending submission.
		if req.Token == "" {
			fields := strings.Fields(r.Header.Get("Authorization"))
			if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || !matchesSecret(fields[1], s.config.EnrollmentToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="enrollment"`)
				controlError(w, http.StatusUnauthorized, "enrollment authentication required")
				return
			}
		}
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
		if matchesSecret(raw, s.config.EnrollmentToken) {
			controlError(w, http.StatusForbidden, "enrollment credential cannot authorize this operation")
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
			actor = auth.Actor
		}
	}
	result, err := s.execute(r.Context(), req, authorization{Actor: actor})
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

// execute dispatches an already authorized public operation to its provider.
// The directory and inventory operations own their signed backend protocols.
func (s *Server) execute(ctx context.Context, req facts.ControlRequest, auth authorization) (*facts.ControlResponse, error) {
	var result facts.ControlResponse
	var err error
	invalid := func(message string) (*facts.ControlResponse, error) {
		return nil, &facts.ServiceError{Status: 400, Message: message}
	}
	switch req.Action {
	case "enroll":
		if req.Host == nil {
			return invalid("host is required")
		}
		result.Host, err = s.enroll(ctx, req.ID, *req.Host, req.Token)
	case "add":
		if req.Host == nil {
			return invalid("host is required")
		}
		result.Host, err = s.addHost(ctx, auth, *req.Host)
	case "list":
		result.Hosts, err = s.hosts(ctx, auth, req.After, req.Limit, req.Pending)
	case "get":
		result.Host, err = s.host(ctx, auth, req.ID)
	case "edit":
		if req.Host == nil {
			return invalid("host is required")
		}
		result.Host, err = s.editHost(ctx, auth, req.ID, req.ExpectedVersion, *req.Host)
	case "approve":
		result.Host, err = s.approveHost(ctx, auth, req.ID, req.ExpectedVersion)
	case "deny":
		result.Host, err = s.denyHost(ctx, auth, req.ID, req.ExpectedVersion)
	case "remove":
		err = s.removeHost(ctx, auth, req.ID, req.ExpectedVersion)
	case "token-create":
		result.Token, err = s.createToken(ctx, auth, req.LifetimeSeconds)
	case "token-revoke":
		err = s.revokeToken(ctx, auth, req.ID)
	case "audit":
		result.Audit, err = s.hostAudit(ctx, auth, req.AuditCursor, req.AuditLimit)
	case "directory-audit":
		result.DirectoryAudit, err = s.directoryAudit(ctx, auth, req.AuditCursor, req.AuditLimit)
	default:
		return invalid("unknown inventory action")
	}
	return &result, err
}
func (s *Server) actor(ctx context.Context, id string) (*facts.Actor, error) {
	if s.config.DirectoryBackendURL != "" {
		return s.directoryActor(ctx, id)
	}
	u, err := s.data.User(ctx, id)
	if err != nil || u == nil {
		return nil, err
	}
	return &facts.Actor{ID: u.ID, UserName: u.UserName, Active: true, Groups: object.GroupNames(u.Groups)}, nil
}
func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	result, err := s.providerCapabilities(r.Context())
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
func (s *Server) authorizeAdmin(ctx context.Context, token string, admins Admins, role string) (authorization, *facts.ServiceError) {
	fail := func(status int, message string) (authorization, *facts.ServiceError) {
		return authorization{}, &facts.ServiceError{Status: status, Message: message}
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
	u, err := s.actor(ctx, claims.UserID)
	if err != nil {
		return fail(503, "directory unavailable")
	}
	if !admins.Allows(u) {
		return fail(403, role+" role required")
	}
	return authorization{Actor: u.ID}, nil
}
