package controlplane

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

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

type TokenValidator interface {
	Validate(context.Context, string) (*oidc.Claims, error)
}
type Admins struct{ Users, Groups []string }

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

// Config keeps identity and administrative grants at control. The directory
// lookup URL is required; optional backend URLs enable the existing built-in
// management capabilities without imposing them on custom fact providers.
type Config struct {
	Key                                                    sshcert.RawPrivateKey
	DirectoryURL, DirectoryBackendURL, InventoryBackendURL string
	Validator                                              TokenValidator
	DirectoryAdmins, InventoryAdmins                       Admins
	SCIMToken                                              string
	TLS                                                    tlsconfig.Config
}
type Server struct {
	config    Config
	data      *facts.DataClient
	control   *facts.ControlClient
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
	if config.SCIMToken != "" && (config.DirectoryBackendURL == "" || strings.ContainsAny(config.SCIMToken, " \t\r\n")) {
		return nil, fmt.Errorf("SCIM requires a directory backend and a bearer token without whitespace")
	}
	s := &Server{config: config, data: data, control: control}
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
	json.NewEncoder(w).Encode(inventoryapi.ControlResponse{Error: message})
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
	var req inventoryapi.ControlRequest
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
	actor, revision := "", directory.Revision("")
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
		claims, err := s.config.Validator.Validate(r.Context(), raw)
		if err != nil {
			controlError(w, 401, "invalid or expired authentication")
			return
		}
		u, rev, err := s.actor(r.Context(), claims.UserID)
		if err != nil {
			controlError(w, 503, "directory unavailable")
			return
		}
		if !admins.Allows(u) {
			controlError(w, 403, role+" role required")
			return
		}
		actor, revision = u.ID, rev
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
func (s *Server) execute(ctx context.Context, req inventoryapi.ControlRequest, auth facts.Authorization) (*inventoryapi.ControlResponse, error) {
	var result inventoryapi.ControlResponse
	var err error
	invalid := func(message string) (*inventoryapi.ControlResponse, error) {
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
		result.Hosts, err = s.control.Hosts(ctx, auth)
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
	case "token-list":
		result.Tokens, err = s.control.Tokens(ctx, auth)
	case "token-revoke":
		err = s.control.RevokeToken(ctx, auth, req.ID)
	case "audit":
		result.Audit, err = s.control.HostAudit(ctx, auth)
	case "directory-users":
		result.DirectoryUsers, err = s.control.Users(ctx, auth)
	case "directory-groups":
		result.Directory, err = s.control.Bindings(ctx, auth)
	case "directory-bind":
		err = s.control.BindGroup(ctx, auth, req.Alias, req.ID, req.Revision)
	case "directory-audit":
		result.DirectoryAudit, err = s.control.DirectoryAudit(ctx, auth, req.AuditAfter, req.AuditLimit)
	default:
		return invalid("unknown inventory action")
	}
	return &result, err
}
func (s *Server) actor(ctx context.Context, id string) (*directory.User, directory.Revision, error) {
	if s.config.DirectoryBackendURL != "" {
		return s.control.Actor(ctx, id)
	}
	u, err := s.data.User(ctx, id)
	if err != nil || u == nil {
		return nil, "", err
	}
	return &directory.User{ID: u.ID, UserName: u.UserName, Active: true, Groups: u.Groups, UserType: u.UserType, Department: u.Department, Organization: u.Organization}, "", nil
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
func (s *Server) scim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")
	if s.config.SCIMToken == "" {
		http.NotFound(w, r)
		return
	}
	fields := strings.Fields(r.Header.Get("Authorization"))
	token := ""
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
		token = fields[1]
	}
	actual, expected := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(s.config.SCIMToken))
	if token == "" || subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		scimError(w, 401, "invalid provisioning credential")
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
	if err != nil || len(body) > 4<<20 {
		scimError(w, 413, "request too large")
		return
	}
	result, err := s.control.Provision(r.Context(), facts.SCIMRequest{Method: r.Method, Target: r.URL.RequestURI(), ContentType: r.Header.Get("Content-Type"), IfMatch: r.Header.Get("If-Match"), Body: body})
	if err != nil {
		controlError(w, 503, "control backend unavailable")
		return
	}
	// Preserve the provisioning protocol's status and metadata without exposing
	// the private service transport or forwarding its authentication headers.
	for name, value := range map[string]string{"Content-Type": result.ContentType, "ETag": result.ETag, "Location": result.Location, "WWW-Authenticate": result.WWWAuthenticate} {
		if value != "" {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(result.Status)
	w.Write(result.Body)
}

func scimError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": fmt.Sprint(status), "detail": detail})
}
