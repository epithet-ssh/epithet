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
	// DeniedSubjects rejects issuance and enrollment for exact,
	// case-sensitive subjects. Changes require restart; retain entries to revoke.
	DeniedSubjects []string
	TLS            tlsconfig.Config
}
type Server struct {
	enrollment       *enrollmentAuthority
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
	directory, err := servicehttp.New(config.DirectoryURL, "/lookup", config.Key, serviceauth.DirectoryAudience, config.TLS)
	if err != nil {
		return nil, err
	}
	enrollment, err := newEnrollmentAuthority(config.Key)
	if err != nil {
		return nil, err
	}
	config.DeniedSubjects = slices.Clone(config.DeniedSubjects)
	s := &Server{config: config, data: data, directory: directory, enrollment: enrollment}
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
	hostPath := strings.HasPrefix(r.URL.Path, "/manage/")
	if r.URL.Path != "/manage" && !hostPath {
		http.NotFound(w, r)
		return
	}
	if !hostPath && r.Method == "GET" {
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
	if (req.Action == "create") != hostPath {
		controlError(w, 405, "host creation requires POST to the host id")
		return
	}
	if hostPath {
		id := strings.TrimPrefix(r.URL.Path, "/manage/")
		if id == "" || strings.Contains(id, "/") || req.ID != id {
			controlError(w, 400, "host id must match its URL")
			return
		}
	}
	auth, rejected := s.authorizeManagement(r, req.Action)
	if rejected != nil {
		if hostPath && rejected.Status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="enrollment"`)
		}
		controlError(w, rejected.Status, rejected.Message)
		return
	}
	result, err := s.execute(r.Context(), req, auth)
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
	case "create":
		if req.Host == nil {
			return invalid("host is required")
		}
		result.Host, err = s.createHost(ctx, auth, req.ID, *req.Host)
	case "list":
		result.Hosts, err = s.hosts(ctx, auth, req.After, req.Limit)
	case "get":
		result.Host, err = s.host(ctx, auth, req.ID)
	case "edit":
		if req.Host == nil {
			return invalid("host is required")
		}
		result.Host, err = s.editHost(ctx, auth, req.ID, req.ExpectedVersion, *req.Host)
	case "remove":
		err = s.removeHost(ctx, auth, req.ID, req.ExpectedVersion)
	case "token-create":
		result.Token, err = s.createToken(req.Subject, req.LifetimeSeconds)
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

// Host creation also accepts a provisioning credential. The provider receives
// the authenticated actor and the same create operation for either credential.
func (s *Server) authorizeManagement(r *http.Request, action string) (authorization, *facts.ServiceError) {
	directory := strings.HasPrefix(action, "directory-")
	if (directory && s.directoryBackend == nil) || (!directory && s.inventory == nil) {
		return authorization{}, &facts.ServiceError{Status: 404, Message: "requested management capability is not configured"}
	}
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return authorization{}, &facts.ServiceError{Status: 401, Message: "authentication required"}
	}
	token := fields[1]
	if directory {
		return s.authorizeAdmin(r.Context(), token, s.config.DirectoryAdmins, "directory-admin")
	}
	if action == "create" {
		if subject, err := s.enrollment.verify(token); err == nil {
			if slices.Contains(s.config.DeniedSubjects, subject) {
				return authorization{}, &facts.ServiceError{Status: 403, Message: "enrollment subject is denied"}
			}
			if !s.admit() {
				return authorization{}, &facts.ServiceError{Status: 429, Message: "enrollment rate limit; retry later"}
			}
			return authorization{Actor: subject}, nil
		}
	}
	if matchesSecret(token, s.config.InventoryToken) {
		return authorization{Actor: "inventory-token"}, nil
	}
	return s.authorizeAdmin(r.Context(), token, s.config.InventoryAdmins, "inventory-admin")
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
