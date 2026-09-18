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
	ErrRevision = errors.New("record changed; reload before retrying")
)

// Proposal is the entire editable authorization record. Admission and ownership
// are server-owned metadata, never fields a host can approve for itself.
type Proposal struct {
	Names         []string          `yaml:"names"`
	Labels        map[string]string `yaml:"labels"`
	Accounts      []string          `yaml:"accounts"`
	PrincipalMode PrincipalMode     `yaml:"principal-mode"`
	Domain        string            `yaml:"domain,omitempty"`
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

// MarshalYAML preserves the distinction between unrestricted accounts (null)
// and an explicit empty account set ([]), both on disk and in the editor.
func (p Proposal) MarshalYAML() (any, error) {
	type plainProposal Proposal
	var node yaml.Node
	if err := node.Encode(plainProposal(p)); err != nil {
		return nil, err
	}
	if p.Accounts == nil {
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value == "accounts" {
				node.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
				break
			}
		}
	}
	return &node, nil
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
		if !d.IsGeneratedHost() && p.PrincipalMode != EpithetPrincipalV1 {
			return fmt.Errorf("named domain %q requires %s", d, EpithetPrincipalV1)
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
	SourceFile string `yaml:"-"`
	Pattern    string `yaml:"-"`

	ID            string    `yaml:"id"`
	Revision      uint64    `yaml:"revision"`
	Status        string    `yaml:"status"`
	Proposal      Proposal  `yaml:"host"`
	CreatedAt     time.Time `yaml:"created-at"`
	UpdatedAt     time.Time `yaml:"updated-at"`
	Source        string    `yaml:"-"`
	ShadowedNames []string  `yaml:"-"`
}

type EnrollmentToken struct {
	ID        string    `yaml:"id"`
	ExpiresAt time.Time `yaml:"expires-at"`
	UsedBy    string    `yaml:"used-by,omitempty"`
	Revoked   bool      `yaml:"revoked"`
}
type AuditEvent struct {
	At       time.Time `yaml:"at"`
	Actor    string    `yaml:"actor"`
	Action   string    `yaml:"action"`
	Resource string    `yaml:"resource"`
}

// Managed loads item files once, then resolves names entirely through indexes.
// Mutations persist one item before updating its indexes under the write lock.
// Files are the source of truth; edit them only while the service is stopped.
type Managed struct {
	mu            sync.RWMutex
	files         *itemFiles
	records       map[string]*itemRecord
	names         map[string]string
	domains       map[string]map[string]*HostRecord
	staticDomains map[string]bool
	pending       int
	hashes        map[string]string
	revision      string
	static        *Static
	failed        error
}

func RandomSecret() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func digest(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (m *Managed) Close() error  { return m.files.Close() }
func (m *Managed) Health() error { m.mu.RLock(); defer m.mu.RUnlock(); return m.failed }

// publish updates only the affected record's index entries. The caller holds
// the write lock and has already committed the file (or is loading at startup).
func (m *Managed) publish(r *itemRecord) {
	id := r.id()
	if old := m.records[id]; old != nil {
		m.unindex(old)
	}
	m.records[id] = r
	if h := r.Host; h != nil {
		if h.Status == "active" {
			for _, name := range h.Proposal.Names {
				m.names[name] = id
			}
			if h.Proposal.Domain != "" {
				if m.domains[h.Proposal.Domain] == nil {
					m.domains[h.Proposal.Domain] = map[string]*HostRecord{}
				}
				m.domains[h.Proposal.Domain][id] = h
			}
		}
		if h.Status == "pending" {
			m.pending++
		}
	}
	data, _ := yaml.Marshal(r)
	m.hashes[id] = digest(string(data))
}
func (m *Managed) unindex(r *itemRecord) {
	h := r.Host
	if h == nil {
		return
	}
	if h.Status == "active" {
		for _, name := range h.Proposal.Names {
			if m.names[name] == h.ID {
				delete(m.names, name)
			}
		}
	}
	if members := m.domains[h.Proposal.Domain]; members != nil {
		delete(members, h.ID)
		if len(members) == 0 {
			delete(m.domains, h.Proposal.Domain)
		}
	}
	if h.Status == "pending" {
		m.pending--
	}
}
func (m *Managed) updateRevision() {
	// This visits small in-memory hashes, not files or record bodies. Resolution
	// reads the resulting fingerprint in O(1), stable across unchanged restarts.
	ids := make([]string, 0, len(m.hashes))
	for id := range m.hashes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	hash := sha256.New()
	for _, id := range ids {
		fmt.Fprintf(hash, "%s:%s\n", id, m.hashes[id])
	}
	m.revision = fmt.Sprintf("managed:sha256:%x", hash.Sum(nil))
}
func (m *Managed) checkIndexes(r *itemRecord) error {
	h := r.Host
	if h == nil {
		return nil
	}
	if h.Status == "active" {
		for _, n := range h.Proposal.Names {
			if owner := m.names[n]; owner != "" && owner != h.ID {
				return fmt.Errorf("%w: name %s is active on hosts %s and %s", ErrConflict, n, owner, h.ID)
			}
		}
		if err := m.checkDomain(h.Proposal, h.ID); err != nil {
			return err
		}
	}
	return nil
}
func (m *Managed) conflict(p Proposal, except string) error {
	if m.staticDomains[p.Domain] {
		return fmt.Errorf("%w: principal domain is already in use", ErrConflict)
	}
	if err := m.checkDomain(p, except); err != nil {
		return err
	}
	for _, n := range p.Names {
		if m.static != nil && m.static.hosts[n] != nil {
			return fmt.Errorf("%w: proposed names are already in use", ErrConflict)
		}
		if owner := m.names[n]; owner != "" && owner != except {
			return fmt.Errorf("%w: proposed names are already in use", ErrConflict)
		}
	}
	return nil
}

// checkDomain preserves per-host identity for generated domains and one set of
// authorization attributes for each shared named domain, including static members.
// Pending proposals impose no constraints until they are approved.
func (m *Managed) checkDomain(p Proposal, except string) error {
	domain := principal.Domain(p.Domain)
	if domain == "" {
		return nil
	}
	if !domain.IsGeneratedHost() {
		if m.static == nil {
			return fmt.Errorf("%w: undeclared domain %q", ErrConflict, domain)
		}
		if _, ok := m.static.domains[domain]; !ok {
			return fmt.Errorf("%w: undeclared domain %q", ErrConflict, domain)
		}
		if policy, ok := m.static.domainPolicies[domain]; ok && !policy.matches(p.Labels, p.Accounts) {
			return fmt.Errorf("%w: domain %q has different authorization attributes from static inventory", ErrConflict, domain)
		}
	}
	for id, member := range m.domains[p.Domain] {
		if id == except {
			continue
		}
		if domain.IsGeneratedHost() {
			return fmt.Errorf("%w: principal domain is already active on host %s", ErrConflict, id)
		}
		policy := domainPolicy{labels: member.Proposal.Labels, accounts: member.Proposal.Accounts}
		if !policy.matches(p.Labels, p.Accounts) {
			return fmt.Errorf("%w: domain %q has different authorization attributes from host %s", ErrConflict, domain, id)
		}
	}
	return nil
}
func cloneHost(h *HostRecord) *HostRecord {
	if h == nil {
		return nil
	}
	out := *h
	out.Proposal.Names = slices.Clone(h.Proposal.Names)
	out.Proposal.Accounts = slices.Clone(h.Proposal.Accounts)
	out.Proposal.Labels = cloneLabels(h.Proposal.Labels)
	out.ShadowedNames = slices.Clone(h.ShadowedNames)
	return &out
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
func cloneItem(r *itemRecord) *itemRecord {
	out := *r
	out.Host = cloneHost(r.Host)
	if r.Token != nil {
		t := *r.Token
		out.Token = &t
	}
	out.Audit = slices.Clone(r.Audit)
	return &out
}

// commit writes the host/token transition and its audit together in one file.
func (m *Managed) commit(r *itemRecord, actor, action string, create bool) error {
	r = cloneItem(r)
	r.Audit = append(r.Audit, AuditEvent{At: time.Now().UTC(), Actor: actor, Action: action, Resource: r.id()})
	if err := m.files.write(r, create); err != nil {
		if create && errors.Is(err, errItemExists) {
			return err
		}
		m.failed = fmt.Errorf("%w; restart after repair: %v", ErrStorage, err)
		return m.failed
	}
	m.publish(r)
	m.updateRevision()
	return nil
}
func (m *Managed) Enroll(p Proposal, token string) (*HostRecord, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return nil, m.failed
	}
	status := "pending"
	var reserved *itemRecord
	if token != "" {
		// The literal token is the filename and the reserved host ID. A host file
		// never grants preapproval, even if its former token has not yet expired.
		if !validID(token) {
			return nil, ErrToken
		}
		reserved = m.records[token]
		if reserved == nil || reserved.Kind != "token" || reserved.Token.Revoked || reserved.Token.UsedBy != "" || !time.Now().Before(reserved.Token.ExpiresAt) {
			return nil, ErrToken
		}
		if err := m.conflict(p, ""); err != nil {
			return nil, err
		}
		status = "active"
	} else if m.pending >= 1000 {
		return nil, fmt.Errorf("pending enrollment queue is full")
	}
	for {
		id := token
		if id == "" {
			var err error
			id, err = m.files.newID()
			if err != nil {
				return nil, err
			}
			if m.records[id] != nil {
				continue
			}
		}
		now := time.Now().UTC()
		h := HostRecord{ID: id, Revision: 1, Status: status, Proposal: p, CreatedAt: now, UpdatedAt: now}
		r := &itemRecord{Version: 2, Kind: "host", Host: &h}
		if reserved != nil {
			r = cloneItem(reserved)
			r.Kind = "host"
			r.Host = &h
			r.Token.UsedBy = id
		}
		err := m.commit(r, "host", "enroll", reserved == nil)
		if errors.Is(err, errItemExists) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return cloneHost(m.records[id].Host), nil
	}
}
func (m *Managed) Change(actor, action, id string, revision uint64, p *Proposal) (*HostRecord, error) {
	if p != nil {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return nil, m.failed
	}
	current := m.records[id]
	if current == nil || current.Host == nil {
		return nil, ErrNotFound
	}
	r := cloneItem(current)
	h := r.Host
	if revision == 0 || h.Revision != revision {
		return nil, ErrRevision
	}
	switch action {
	case "edit":
		if p == nil {
			return nil, fmt.Errorf("host proposal is required")
		}
		if h.Status != "pending" && h.Status != "active" {
			return nil, fmt.Errorf("only pending or active records can be edited")
		}
		if h.Status == "active" {
			if err := m.conflict(*p, id); err != nil {
				return nil, err
			}
		}
		h.Proposal = *p
	case "approve":
		if h.Status != "pending" {
			return nil, fmt.Errorf("only pending records can be approved")
		}
		if err := m.conflict(h.Proposal, id); err != nil {
			return nil, err
		}
		h.Status = "active"
	case "deny":
		if h.Status != "pending" {
			return nil, fmt.Errorf("only pending records can be denied")
		}
		h.Status = "denied"
	case "remove":
		if err := m.files.remove(id); err != nil {
			m.failed = fmt.Errorf("%w; restart after repair: %v", ErrStorage, err)
			return nil, m.failed
		}
		m.unindex(current)
		delete(m.records, id)
		delete(m.hashes, id)
		m.updateRevision()
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown inventory action")
	}
	h.Revision++
	h.UpdatedAt = time.Now().UTC()
	if err := m.commit(r, actor, action, false); err != nil {
		return nil, err
	}
	return cloneHost(m.records[id].Host), nil
}
func (m *Managed) List() ([]HostRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failed != nil {
		return nil, m.failed
	}
	hosts := []HostRecord{}
	for _, r := range m.records {
		if r.Host != nil {
			h := cloneHost(r.Host)
			h.Source = "dynamic"
			h.SourceFile = m.files.itemPath(h.ID)
			if m.static != nil {
				for _, n := range h.Proposal.Names {
					if m.static.hosts[n] != nil {
						h.ShadowedNames = append(h.ShadowedNames, n)
					}
				}
			}
			hosts = append(hosts, *h)
		}
	}
	if m.static != nil {
		hosts = append(hosts, m.static.Records()...)
	}
	slices.SortFunc(hosts, func(a, b HostRecord) int { return strings.Compare(a.ID, b.ID) })
	return hosts, nil
}
func (m *Managed) CreateToken(actor string, lifetime time.Duration) (EnrollmentToken, error) {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return EnrollmentToken{}, fmt.Errorf("token lifetime must be positive and no more than 24h")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return EnrollmentToken{}, m.failed
	}
	for {
		id, err := m.files.newID()
		if err != nil {
			return EnrollmentToken{}, err
		}
		if m.records[id] != nil {
			continue
		}
		token := EnrollmentToken{ID: id, ExpiresAt: time.Now().UTC().Add(lifetime)}
		err = m.commit(&itemRecord{Version: 2, Kind: "token", Token: &token}, actor, "token-create", true)
		if errors.Is(err, errItemExists) {
			continue
		}
		if err != nil {
			return EnrollmentToken{}, err
		}
		return token, nil
	}
}
func (m *Managed) Tokens() ([]EnrollmentToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failed != nil {
		return nil, m.failed
	}
	tokens := []EnrollmentToken{}
	for _, r := range m.records {
		if r.Token != nil {
			tokens = append(tokens, *r.Token)
		}
	}
	slices.SortFunc(tokens, func(a, b EnrollmentToken) int { return strings.Compare(a.ID, b.ID) })
	return tokens, nil
}
func (m *Managed) RevokeToken(actor, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return m.failed
	}
	old := m.records[id]
	if old == nil || old.Token == nil {
		return ErrNotFound
	}
	r := cloneItem(old)
	r.Token.Revoked = true
	return m.commit(r, actor, "token-revoke", false)
}
func (m *Managed) Audit() ([]AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failed != nil {
		return nil, m.failed
	}
	events := []AuditEvent{}
	for _, r := range m.records {
		events = append(events, r.Audit...)
	}
	slices.SortStableFunc(events, func(a, b AuditEvent) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		return strings.Compare(a.Resource, b.Resource)
	})
	return events, nil
}

// LookupHost resolves the host and its revision under the same read lock.
func (m *Managed) LookupHost(ctx context.Context, name string) (*ResolvedHost, string, error) {
	name = hostpattern.NormalizeName(name)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failed != nil {
		return nil, "", m.failed
	}
	if m.static != nil && m.static.hosts[name] != nil {
		return m.static.hosts[name], m.static.InventoryRevision(), nil
	}
	revision := m.revision
	if m.static != nil {
		revision = m.static.InventoryRevision() + ":" + revision
	}
	if id := m.names[name]; id != "" {
		p := m.records[id].Host.Proposal
		domain := principal.Domain(p.Domain)
		return &ResolvedHost{Policy: resolvedPolicyHost(slices.Clone(p.Names), domain, cloneLabels(p.Labels), slices.Clone(p.Accounts)), PrincipalMode: p.PrincipalMode, Domain: domain}, revision, nil
	}
	if m.static != nil {
		h, _, err := m.static.LookupHost(ctx, name)
		return h, revision, err
	}
	return nil, revision, nil
}
