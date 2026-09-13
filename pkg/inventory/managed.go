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
	RetiredNames   []string  `yaml:"retired-names,omitempty" json:"retired-names,omitempty"`
}
type EnrollmentToken struct {
	ID        string    `yaml:"id" json:"id"`
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

// Managed loads item files once, then resolves names entirely through indexes.
// Mutations persist one item before updating its indexes under the write lock.
// Files are the source of truth; edit them only while the service is stopped.
type Managed struct {
	mu            sync.RWMutex
	files         *itemFiles
	records       map[string]*itemRecord
	names         map[string]*nameClaims
	credentials   map[string]string
	domains       map[string]string
	staticDomains map[string]bool
	pending       int
	hashes        map[string]string
	revision      string
	legacy        legacyMetadata
	static        *Static
	failed        error
}

type nameClaims struct {
	approved string
	owners   map[string]struct{}
}

func RandomSecret() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func digest(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func validID(id string) bool {
	if len(id) != 64 && len(id) != 24 {
		return false
	} // 24-character IDs belong to migrated hosts.
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
		for _, name := range append(slices.Clone(h.Proposal.Names), h.RetiredNames...) {
			entry := m.names[name]
			if entry == nil {
				entry = &nameClaims{owners: map[string]struct{}{}}
				m.names[name] = entry
			}
			entry.owners[id] = struct{}{}
		}
		if h.Status == "approved" {
			for _, name := range h.Proposal.Names {
				m.names[name].approved = id
			}
			if h.Proposal.Domain != "" {
				m.domains[h.Proposal.Domain] = id
			}
		}
		if h.Status == "pending" {
			m.pending++
		}
		if h.Status == "pending" || h.Status == "approved" {
			m.credentials[h.CredentialHash] = id
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
	for _, name := range append(slices.Clone(h.Proposal.Names), h.RetiredNames...) {
		entry := m.names[name]
		if entry == nil {
			continue
		}
		delete(entry.owners, h.ID)
		if entry.approved == h.ID {
			entry.approved = ""
		}
		if len(entry.owners) == 0 {
			delete(m.names, name)
		}
	}
	if m.domains[h.Proposal.Domain] == h.ID {
		delete(m.domains, h.Proposal.Domain)
	}
	if m.credentials[h.CredentialHash] == h.ID {
		delete(m.credentials, h.CredentialHash)
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
	data, _ := yaml.Marshal(m.legacy)
	hash.Write(data)
	m.revision = fmt.Sprintf("managed:sha256:%x", hash.Sum(nil))
}
func (m *Managed) checkIndexes(r *itemRecord) error {
	h := r.Host
	if h == nil {
		return nil
	}
	if h.Status == "pending" || h.Status == "approved" {
		if owner := m.credentials[h.CredentialHash]; owner != "" && owner != h.ID {
			return fmt.Errorf("duplicate enrollment credential on hosts %s and %s", owner, h.ID)
		}
	}
	if h.Status == "approved" {
		for _, n := range h.Proposal.Names {
			if entry := m.names[n]; entry != nil && entry.approved != "" && entry.approved != h.ID {
				return fmt.Errorf("%w: name %s is approved on hosts %s and %s", ErrConflict, n, entry.approved, h.ID)
			}
		}
		if owner := m.domains[h.Proposal.Domain]; h.Proposal.Domain != "" && owner != "" && owner != h.ID {
			return fmt.Errorf("%w: principal domain is approved on hosts %s and %s", ErrConflict, owner, h.ID)
		}
	}
	return nil
}
func (m *Managed) conflict(p Proposal, except string) error {
	if p.Domain != "" && (m.staticDomains[p.Domain] || (m.domains[p.Domain] != "" && m.domains[p.Domain] != except)) {
		return fmt.Errorf("%w: principal domain is already in use", ErrConflict)
	}
	for _, n := range p.Names {
		if m.static != nil && m.static.hosts[n] != nil {
			return fmt.Errorf("%w: proposed names are already in use", ErrConflict)
		}
		if entry := m.names[n]; entry != nil && entry.approved != "" && entry.approved != except {
			return fmt.Errorf("%w: proposed names are already in use", ErrConflict)
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
	out.RetiredNames = slices.Clone(h.RetiredNames)
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return nil, m.failed
	}
	hash := digest(credential)
	if id := m.credentials[hash]; id != "" {
		return cloneHost(m.records[id].Host), nil
	}
	if err := m.conflict(p, ""); err != nil {
		return nil, err
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
		status = "approved"
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
		h := HostRecord{ID: id, Revision: 1, Status: status, Proposal: p, CredentialHash: hash, CreatedAt: now, UpdatedAt: now}
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
		if h.Status != "pending" && h.Status != "approved" {
			return nil, fmt.Errorf("only pending or approved records can be edited")
		}
		if h.Status == "approved" {
			if err := m.conflict(*p, id); err != nil {
				return nil, err
			}
		}
		for _, n := range h.Proposal.Names {
			if !slices.Contains(p.Names, n) && !slices.Contains(h.RetiredNames, n) {
				h.RetiredNames = append(h.RetiredNames, n)
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
		h.Status = "approved"
	case "deny":
		if h.Status != "pending" {
			return nil, fmt.Errorf("only pending records can be denied")
		}
		h.Status = "denied"
	case "remove":
		h.Status = "removed"
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
func (m *Managed) CreateToken(actor string, lifetime time.Duration) (EnrollmentToken, string, error) {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return EnrollmentToken{}, "", fmt.Errorf("token lifetime must be positive and no more than 24h")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return EnrollmentToken{}, "", m.failed
	}
	for {
		id, err := m.files.newID()
		if err != nil {
			return EnrollmentToken{}, "", err
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
			return EnrollmentToken{}, "", err
		}
		return token, id, nil
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
	events := slices.Clone(m.legacy.Audit)
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
func (m *Managed) LookupHost(ctx context.Context, name string) (*ResolvedHost, error) {
	h, _, err := m.LookupHostSnapshot(ctx, name)
	return h, err
}
func (m *Managed) LookupHostSnapshot(ctx context.Context, name string) (*ResolvedHost, string, error) {
	name = hostpattern.NormalizeName(name)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.static != nil && m.static.hosts[name] != nil {
		return m.static.hosts[name], m.static.InventoryRevision(), nil
	}
	if m.failed != nil {
		return nil, "", m.failed
	}
	revision := m.revision
	if m.static != nil {
		revision = m.static.InventoryRevision() + ":" + revision
	}
	if entry := m.names[name]; entry != nil {
		if entry.approved == "" {
			return nil, revision, nil
		}
		p := m.records[entry.approved].Host.Proposal
		return &ResolvedHost{Policy: Host{Names: slices.Clone(p.Names), Labels: cloneLabels(p.Labels), Accounts: slices.Clone(p.Accounts)}, PrincipalMode: p.PrincipalMode, Domain: principal.Domain(p.Domain)}, revision, nil
	}
	if m.static != nil {
		h, err := m.static.LookupHost(ctx, name)
		return h, revision, err
	}
	return nil, revision, nil
}
