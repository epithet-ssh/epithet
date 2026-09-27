package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/factservice"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
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
	config                             Config
	directory                          *factservice.Client
	directoryBackend, inventoryBackend *serviceauth.Client
	mu                                 sync.Mutex
	allowance                          float64
	last                               time.Time
}

func New(config Config) (*Server, error) {
	if config.Validator == nil {
		return nil, fmt.Errorf("control OIDC validator is required")
	}
	c, err := factservice.NewClient(config.DirectoryURL, config.Key, serviceauth.DirectoryAudience, config.TLS)
	if err != nil {
		return nil, err
	}
	s := &Server{config: config, directory: c}
	if config.DirectoryBackendURL != "" {
		s.directoryBackend, err = serviceauth.NewClient(config.DirectoryBackendURL, config.Key, serviceauth.DirectoryAudience, config.TLS)
		if err != nil {
			return nil, err
		}
	}
	if config.InventoryBackendURL != "" {
		s.inventoryBackend, err = serviceauth.NewClient(config.InventoryBackendURL, config.Key, serviceauth.InventoryAudience, config.TLS)
		if err != nil {
			return nil, err
		}
	}
	if config.SCIMToken != "" && (s.directoryBackend == nil || strings.ContainsAny(config.SCIMToken, " \t\r\n")) {
		return nil, fmt.Errorf("SCIM requires a directory backend and a bearer token without whitespace")
	}
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
	backend, admins := s.inventoryBackend, s.config.InventoryAdmins
	role := "inventory-admin"
	if isDirectory {
		backend, admins = s.directoryBackend, s.config.DirectoryAdmins
		role = "directory-admin"
	}
	if backend == nil {
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
	data, err = json.Marshal(request{req, revision})
	if err != nil {
		controlError(w, 400, "invalid control request")
		return
	}
	resp, err := backend.Do(r.Context(), "POST", "/manage", nil, data, actor)
	s.forward(w, resp, err)
}
func (s *Server) actor(ctx context.Context, id string) (*directory.User, directory.Revision, error) {
	if s.directoryBackend != nil {
		resp, err := s.directoryBackend.Do(ctx, "GET", "/actor", url.Values{"id": {id}}, nil, "")
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, "", fmt.Errorf("actor lookup returned HTTP %d", resp.StatusCode)
		}
		var result actorFacts
		dec := json.NewDecoder(io.LimitReader(resp.Body, wire.MaxBodySize))
		if err := dec.Decode(&result); err != nil {
			return nil, "", err
		}
		if result.User != nil && result.User.ID != id {
			return nil, "", fmt.Errorf("actor identity mismatch")
		}
		return result.User, result.Revision, nil
	}
	u, err := s.directory.User(ctx, id)
	if err != nil || u == nil {
		return nil, "", err
	}
	return &directory.User{ID: u.ID, UserName: u.UserName, Active: true, Groups: u.Groups, UserType: u.UserType, Department: u.Department, Organization: u.Organization}, "", nil
}
func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	result := inventoryapi.Capabilities{Version: 1, Capabilities: []string{"admin"}}
	for _, backend := range []*serviceauth.Client{s.directoryBackend, s.inventoryBackend} {
		if backend == nil {
			continue
		}
		resp, err := backend.Do(r.Context(), "GET", "/manage", nil, nil, "")
		if err != nil {
			controlError(w, 503, "control backend unavailable")
			return
		}
		var caps inventoryapi.Capabilities
		err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&caps)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || caps.Version != 1 {
			controlError(w, 503, "invalid backend capabilities")
			return
		}
		for _, cap := range caps.Capabilities {
			if !slices.Contains(result.Capabilities, cap) {
				result.Capabilities = append(result.Capabilities, cap)
			}
		}
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
	// The signed envelope also binds SCIM preconditions and its query parameters.
	data, err := json.Marshal(scimRequest{r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type"), r.Header.Get("If-Match"), body})
	if err != nil {
		scimError(w, 400, "invalid request")
		return
	}
	resp, err := s.directoryBackend.Do(r.Context(), "POST", "/scim", nil, data, "")
	s.forward(w, resp, err)
}
func (s *Server) forward(w http.ResponseWriter, resp *http.Response, err error) {
	if err != nil {
		controlError(w, 503, "control backend unavailable")
		return
	}
	defer resp.Body.Close()
	// Preserve public SCIM ETags, locations, and response formats. Never forward
	// private authentication headers or relax the public no-store requirement.
	for _, name := range []string{"Content-Type", "ETag", "Location", "WWW-Authenticate"} {
		if v := resp.Header.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func scimError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": fmt.Sprint(status), "detail": detail})
}
