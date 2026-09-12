package inventory

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"gopkg.in/yaml.v3"
)

var (
	ErrStorage  = errors.New("managed inventory storage unavailable")
	ErrConflict = errors.New("inventory conflict")
	ErrNotFound = errors.New("inventory record not found")
	ErrToken    = errors.New("invalid, expired, revoked, or used enrollment token")
	errNoChange = errors.New("no inventory change")
	ErrRevision = errors.New("record changed; reload before retrying")
)

// Proposal is the entire editable authorization record. Admission and ownership
// are server-owned metadata, never fields a host can approve for itself.
type Proposal struct {
	Names         []string          `yaml:"names" json:"names"`
	Labels        map[string]string `yaml:"labels" json:"labels"`
	Accounts      []string          `yaml:"accounts" json:"accounts"`
	PrincipalMode PrincipalMode     `yaml:"principal-mode" json:"principal-mode"`
	Domain        string            `yaml:"domain,omitempty" json:"domain,omitempty"`
}

// UnmarshalYAML applies the same field-presence contract to on-disk snapshots
// and editor proposals. Accidentally deleting accounts must not broaden access.
func (p *Proposal) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("host must be a YAML mapping")
	}
	accounts := false
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "accounts":
			accounts = true
		case "names", "labels", "principal-mode", "domain":
		default:
			return fmt.Errorf("unknown host field %q", node.Content[i].Value)
		}
	}
	if !accounts {
		return fmt.Errorf("accounts is required: use [], a list, or explicit null")
	}
	type plainProposal Proposal
	var raw plainProposal
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*p = Proposal(raw)
	return nil
}

func (p *Proposal) Validate() error {
	if len(p.Names) == 0 || len(p.Names) > 64 {
		return fmt.Errorf("provide between 1 and 64 exact DNS names")
	}
	seen := map[string]bool{}
	for i, n := range p.Names {
		n = hostpattern.NormalizeName(n)
		if len(n) == 0 || len(n) > 253 {
			return fmt.Errorf("invalid DNS name %q", n)
		}
		for _, label := range strings.Split(n, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return fmt.Errorf("invalid DNS name %q", n)
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
					return fmt.Errorf("invalid exact DNS name %q", n)
				}
			}
		}
		if seen[n] {
			return fmt.Errorf("duplicate DNS name %q", n)
		}
		seen[n] = true
		p.Names[i] = n
	}
	slices.Sort(p.Names)
	if p.PrincipalMode == "" {
		return fmt.Errorf("principal-mode is required")
	}
	if err := p.PrincipalMode.Validate(); err != nil {
		return err
	}
	if p.Domain != "" {
		d, err := principal.ParseDomain(p.Domain)
		if err != nil {
			return err
		}
		if !d.IsGeneratedHost() {
			return fmt.Errorf("managed enrollment currently requires a generated per-host domain")
		}
	}
	if p.PrincipalMode == EpithetPrincipalV1 && p.Domain == "" {
		return fmt.Errorf("domain is required for destination-bound principals")
	}
	seen = map[string]bool{}
	for _, a := range p.Accounts {
		if a == "" || strings.ContainsAny(a, " \t\r\n,:") || strings.IndexFunc(a, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || seen[a] {
			return fmt.Errorf("invalid or duplicate account %q", a)
		}
		seen[a] = true
	}
	return nil
}

// ParseProposal distinguishes an explicit null (ungrounded) account set from
// a missing field, and refuses trailing YAML documents and unknown fields.
func ParseProposal(data []byte) (Proposal, error) {
	var p Proposal
	if err := DecodeYAML(data, &p); err != nil {
		return p, err
	}
	var fields map[string]yaml.Node
	if err := yaml.Unmarshal(data, &fields); err != nil {
		return p, err
	}
	if _, ok := fields["accounts"]; !ok {
		return p, fmt.Errorf("accounts is required: use [] for none, a list, or explicit null for ungrounded")
	}
	return p, p.Validate()
}
func DecodeYAML(data []byte, dst any) error {
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected exactly one YAML document")
	}
	return nil
}

type HostRecord struct {
	SourceFile string `yaml:"-" json:"source-file,omitempty"`
	Pattern    string `yaml:"-" json:"pattern,omitempty"`

	ID             string    `yaml:"id" json:"id"`
	Revision       uint64    `yaml:"revision" json:"revision"`
	Status         string    `yaml:"status" json:"status"`
	Proposal       Proposal  `yaml:"host" json:"host"`
	CredentialHash string    `yaml:"credential-hash" json:"-"`
	CreatedAt      time.Time `yaml:"created-at" json:"created-at"`
	UpdatedAt      time.Time `yaml:"updated-at" json:"updated-at"`
	Source         string    `yaml:"-" json:"source,omitempty"`
	ShadowedNames  []string  `yaml:"-" json:"shadowed-names,omitempty"`
}
type EnrollmentToken struct {
	ID        string    `yaml:"id" json:"id"`
	Hash      string    `yaml:"hash" json:"-"`
	ExpiresAt time.Time `yaml:"expires-at" json:"expires-at"`
	UsedBy    string    `yaml:"used-by,omitempty" json:"used-by,omitempty"`
	Revoked   bool      `yaml:"revoked" json:"revoked"`
}
type AuditEvent struct {
	At       time.Time `yaml:"at" json:"at"`
	Actor    string    `yaml:"actor" json:"actor"`
	Action   string    `yaml:"action" json:"action"`
	Resource string    `yaml:"resource" json:"resource"`
}
type managedState struct {
	Version      int               `yaml:"version"`
	Revision     uint64            `yaml:"revision"`
	Hosts        []HostRecord      `yaml:"hosts"`
	Tokens       []EnrollmentToken `yaml:"tokens"`
	BlockedNames []string          `yaml:"blocked-names"`
	Audit        []AuditEvent      `yaml:"audit"`
}

// Managed uses a single durable snapshot per mutation. All reads are snapshots
// of committed state, and one process owns the directory for its lifetime.
// Files may be edited for experiments ONLY with that process stopped.
type Managed struct {
	revision string
	mu       sync.RWMutex
	path     string
	lock     *os.File
	state    managedState
	static   *Static
	failed   error
}

func OpenManaged(dir string, static *Static) (*Managed, error) {
	return openManaged(dir, static, false)
}

// OpenManagedWithStaticFallback retains the exclusive lock but disables managed
// operations when the snapshot is unreadable. Static exact hosts and directory
// records can still support recovery. Lock/directory setup failures remain fatal.
func OpenManagedWithStaticFallback(dir string, static *Static) (*Managed, error) {
	return openManaged(dir, static, true)
}
func openManaged(dir string, static *Static, fallback bool) (*Managed, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "inventory.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockManagedFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("inventory state is already in use: %w", err)
	}
	m := &Managed{path: filepath.Join(dir, "inventory.yaml"), lock: f, static: static, state: managedState{Version: 1}}
	data, err := os.ReadFile(m.path)
	if err == nil {
		err = DecodeYAML(data, &m.state)
	} else if errors.Is(err, os.ErrNotExist) {
		err = m.persist(m.state)
	}
	if err == nil {
		err = m.validateState()
	}
	if err != nil {
		if fallback {
			m.failed = fmt.Errorf("%w: %v", ErrStorage, err)
			m.state = managedState{}
			return m, nil
		}
		f.Close()
		return nil, fmt.Errorf("opening managed inventory: %w", err)
	}
	stateBytes, _ := yaml.Marshal(m.state)
	m.revision = "managed:sha256:" + digest(string(stateBytes))
	return m, nil
}
func (m *Managed) Close() error  { return m.lock.Close() }
func (m *Managed) Health() error { m.mu.RLock(); defer m.mu.RUnlock(); return m.failed }
func (m *Managed) validateState() error {
	if m.state.Version != 1 {
		return fmt.Errorf("unsupported state version %d", m.state.Version)
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	credentials := map[string]bool{}
	for i := range m.state.Hosts {
		h := &m.state.Hosts[i]
		if h.ID == "" || ids[h.ID] || h.Revision == 0 || len(h.CredentialHash) != 64 {
			return fmt.Errorf("invalid host metadata")
		}
		ids[h.ID] = true
		if err := h.Proposal.Validate(); err != nil {
			return err
		}
		switch h.Status {
		case "pending", "approved", "denied", "removed":
		default:
			return fmt.Errorf("invalid admission state %q", h.Status)
		}
		if h.Status == "approved" || h.Status == "pending" {
			if credentials[h.CredentialHash] {
				return fmt.Errorf("duplicate enrollment credential")
			}
			credentials[h.CredentialHash] = true
		}
		if h.Status == "approved" {
			for _, n := range h.Proposal.Names {
				if names[n] {
					return ErrConflict
				}
				names[n] = true
			}
		}
	}
	ids = map[string]bool{}
	for _, t := range m.state.Tokens {
		if t.ID == "" || ids[t.ID] || len(t.Hash) != 64 || t.ExpiresAt.IsZero() {
			return fmt.Errorf("invalid token metadata")
		}
		ids[t.ID] = true
	}
	return nil
}
func RandomSecret() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func digest(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func newID() (string, error) {
	s, err := RandomSecret()
	if err != nil {
		return "", err
	}
	return s[:24], nil
}
func (m *Managed) persist(s managedState) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(m.path), ".inventory-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), m.path); err != nil {
		return err
	}
	return syncManagedDir(filepath.Dir(m.path))
}
func (m *Managed) mutate(actor, action string, fn func(*managedState) (string, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return m.failed
	}
	data, _ := yaml.Marshal(m.state)
	var next managedState
	if err := DecodeYAML(data, &next); err != nil {
		return err
	}
	resource, err := fn(&next)
	if errors.Is(err, errNoChange) {
		return nil
	}
	if err != nil {
		return err
	}
	next.Revision++
	next.Audit = append(next.Audit, AuditEvent{time.Now().UTC(), actor, action, resource})
	if err := m.persist(next); err != nil {
		m.failed = fmt.Errorf("%w; restart after repair: %v", ErrStorage, err)
		return m.failed
	}
	// Detach caller-owned proposals and returned records from committed state.
	data, _ = yaml.Marshal(next)
	var committed managedState
	if err := DecodeYAML(data, &committed); err != nil {
		m.failed = err
		return err
	}
	m.state = committed
	m.revision = "managed:sha256:" + digest(string(data))
	return nil
}
func (m *Managed) conflict(s *managedState, p Proposal, except string) error {
	// Generated principal domains identify individual machines. Sharing one
	// would make destination-bound certificates portable between those machines.
	if p.Domain != "" {
		if m.static != nil {
			for _, h := range m.static.hosts {
				if string(h.Domain) == p.Domain {
					return fmt.Errorf("%w: principal domain is already in use", ErrConflict)
				}
			}
		}
		for _, h := range s.Hosts {
			if h.ID != except && h.Status == "approved" && h.Proposal.Domain == p.Domain {
				return fmt.Errorf("%w: principal domain is already in use", ErrConflict)
			}
		}
	}
	for _, n := range p.Names {
		if m.static != nil && m.static.hosts[n] != nil {
			return fmt.Errorf("%w: proposed names are already in use", ErrConflict)
		}
		for _, h := range s.Hosts {
			if h.ID != except && h.Status == "approved" && slices.Contains(h.Proposal.Names, n) {
				return fmt.Errorf("%w: proposed names are already in use", ErrConflict)
			}
		}
	}
	return nil
}
func (m *Managed) Enroll(p Proposal, credential, token string) (*HostRecord, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(credential) != 64 {
		return nil, fmt.Errorf("invalid host enrollment credential")
	}
	if _, err := hex.DecodeString(credential); err != nil {
		return nil, fmt.Errorf("invalid host enrollment credential")
	}
	var result HostRecord
	err := m.mutate("host", "enroll", func(s *managedState) (string, error) {
		hash := digest(credential)
		for _, h := range s.Hosts {
			if h.CredentialHash == hash && (h.Status == "pending" || h.Status == "approved") {
				data, _ := yaml.Marshal(h)
				if err := yaml.Unmarshal(data, &result); err != nil {
					return "", err
				}
				return h.ID, errNoChange
			}
		}
		if err := m.conflict(s, p, ""); err != nil {
			return "", err
		}
		status := "pending"
		tokenIndex := -1
		if token != "" {
			for i, t := range s.Tokens {
				if t.Hash == digest(token) && !t.Revoked && t.UsedBy == "" && time.Now().Before(t.ExpiresAt) {
					tokenIndex = i
					break
				}
			}
			if tokenIndex < 0 {
				return "", ErrToken
			}
			status = "approved"
		}
		// A finite admission queue bounds anonymous disk growth. Denied/removed
		// records remain as audit and wildcard tombstones.
		pending := 0
		for _, h := range s.Hosts {
			if h.Status == "pending" {
				pending++
			}
		}
		if status == "pending" && pending >= 1000 {
			return "", fmt.Errorf("pending enrollment queue is full")
		}
		id, err := newID()
		if err != nil {
			return "", err
		}
		now := time.Now().UTC()
		result = HostRecord{ID: id, Revision: 1, Status: status, Proposal: p, CredentialHash: hash, CreatedAt: now, UpdatedAt: now}
		s.Hosts = append(s.Hosts, result)
		if tokenIndex >= 0 {
			s.Tokens[tokenIndex].UsedBy = result.ID
		}
		return result.ID, nil
	})
	return &result, err
}
func findRecord(s *managedState, id string) (*HostRecord, error) {
	for i := range s.Hosts {
		if s.Hosts[i].ID == id {
			return &s.Hosts[i], nil
		}
	}
	return nil, ErrNotFound
}
func (m *Managed) Change(actor, action, id string, revision uint64, p *Proposal) (*HostRecord, error) {
	var result HostRecord
	if p != nil {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	err := m.mutate(actor, action, func(s *managedState) (string, error) {
		h, err := findRecord(s, id)
		if err != nil {
			return "", err
		}
		if revision == 0 || h.Revision != revision {
			return "", ErrRevision
		}
		switch action {
		case "edit":
			if p == nil {
				return "", fmt.Errorf("host proposal is required")
			}
			if h.Status != "pending" && h.Status != "approved" {
				return "", fmt.Errorf("only pending or approved records can be edited")
			}
			if h.Status == "approved" {
				if err := m.conflict(s, *p, id); err != nil {
					return "", err
				}
			}
			for _, n := range h.Proposal.Names {
				if !slices.Contains(p.Names, n) {
					s.BlockedNames = append(s.BlockedNames, n)
				}
			}
			h.Proposal = *p
		case "approve":
			if h.Status != "pending" {
				return "", fmt.Errorf("only pending records can be approved")
			}
			if err := m.conflict(s, h.Proposal, id); err != nil {
				return "", err
			}
			h.Status = "approved"
		case "deny":
			if h.Status != "pending" {
				return "", fmt.Errorf("only pending records can be denied")
			}
			h.Status = "denied"
		case "remove":
			h.Status = "removed"
		default:
			return "", fmt.Errorf("unknown inventory action")
		}
		h.Revision++
		h.UpdatedAt = time.Now().UTC()
		result = *h
		return id, nil
	})
	return &result, err
}
func (m *Managed) List() ([]HostRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failed != nil {
		return nil, m.failed
	}
	data, _ := yaml.Marshal(m.state.Hosts)
	var hosts []HostRecord
	if err := yaml.Unmarshal(data, &hosts); err != nil {
		return nil, err
	}
	for i := range hosts {
		hosts[i].Source = "dynamic"
		if m.static != nil {
			for _, n := range hosts[i].Proposal.Names {
				if m.static.hosts[n] != nil {
					hosts[i].ShadowedNames = append(hosts[i].ShadowedNames, n)
				}
			}
		}
	}
	if m.static != nil {
		hosts = append(hosts, m.static.Records()...)
	}
	return hosts, nil
}
func (m *Managed) CreateToken(actor string, lifetime time.Duration) (EnrollmentToken, string, error) {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return EnrollmentToken{}, "", fmt.Errorf("token lifetime must be positive and no more than 24h")
	}
	secret, err := RandomSecret()
	if err != nil {
		return EnrollmentToken{}, "", err
	}
	id, err := newID()
	if err != nil {
		return EnrollmentToken{}, "", err
	}
	t := EnrollmentToken{ID: id, Hash: digest(secret), ExpiresAt: time.Now().UTC().Add(lifetime)}
	err = m.mutate(actor, "token-create", func(s *managedState) (string, error) { s.Tokens = append(s.Tokens, t); return t.ID, nil })
	return t, secret, err
}
func (m *Managed) Tokens() ([]EnrollmentToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failed != nil {
		return nil, m.failed
	}
	return slices.Clone(m.state.Tokens), nil
}
func (m *Managed) RevokeToken(actor, id string) error {
	return m.mutate(actor, "token-revoke", func(s *managedState) (string, error) {
		for i := range s.Tokens {
			if s.Tokens[i].ID == id {
				s.Tokens[i].Revoked = true
				return id, nil
			}
		}
		return "", ErrNotFound
	})
}
func (m *Managed) Audit() ([]AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failed != nil {
		return nil, m.failed
	}
	return slices.Clone(m.state.Audit), nil
}
func (m *Managed) LookupHost(ctx context.Context, name string) (*ResolvedHost, error) {
	h, _, err := m.LookupHostSnapshot(ctx, name)
	return h, err
}
func (m *Managed) LookupHostSnapshot(ctx context.Context, name string) (*ResolvedHost, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Static exact records remain usable even after a managed write failure.
	if m.static != nil && m.static.hosts[name] != nil {
		return m.static.hosts[name], m.static.InventoryRevision(), nil
	}
	if m.failed != nil {
		return nil, "", m.failed
	}
	rev := m.revision
	if m.static != nil {
		rev = m.static.InventoryRevision() + ":" + rev
	}
	blocked := slices.Contains(m.state.BlockedNames, name)
	for _, h := range m.state.Hosts {
		if !slices.Contains(h.Proposal.Names, name) {
			continue
		}
		blocked = true
		if h.Status == "approved" {
			p := h.Proposal
			return &ResolvedHost{Policy: Host{Names: slices.Clone(p.Names), Labels: cloneLabels(p.Labels), Accounts: slices.Clone(p.Accounts)}, PrincipalMode: p.PrincipalMode, Domain: principal.Domain(p.Domain)}, rev, nil
		}
	}
	if blocked {
		return nil, rev, nil
	}
	if m.static != nil {
		h, err := m.static.LookupHost(ctx, name)
		return h, rev, err
	}
	return nil, rev, nil
}
func cloneLabels(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	m := map[string]string{}
	for k, v := range src {
		m[k] = v
	}
	return m
}
