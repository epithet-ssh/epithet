package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"gopkg.in/yaml.v3"
)

var errItemExists = errors.New("inventory item already exists")

// An unused token and its eventual host occupy the same file. Token metadata
// and per-item audit history remain in the host file after redemption.
type itemRecord struct {
	Version int              `yaml:"version"`
	Kind    string           `yaml:"kind"`
	Host    *HostRecord      `yaml:"host,omitempty"`
	Token   *EnrollmentToken `yaml:"token,omitempty"`
	Audit   []AuditEvent     `yaml:"audit,omitempty"`
}

func (r *itemRecord) id() string {
	if r.Host != nil {
		return r.Host.ID
	}
	if r.Token != nil {
		return r.Token.ID
	}
	return ""
}
func (r *itemRecord) validate(id string) error {
	if r.Version != 2 {
		return fmt.Errorf("unsupported item version %d", r.Version)
	}
	if !validID(id) || r.id() != id {
		return fmt.Errorf("record ID must match its filename")
	}
	switch r.Kind {
	case "token":
		if r.Token == nil || r.Host != nil {
			return fmt.Errorf("token record requires token metadata and no host")
		}
	case "host":
		if r.Host == nil {
			return fmt.Errorf("host record is missing its host")
		}
	default:
		return fmt.Errorf("unknown item kind %q", r.Kind)
	}
	if t := r.Token; t != nil {
		if t.ID != id || t.ExpiresAt.IsZero() {
			return fmt.Errorf("invalid token metadata")
		}
		if r.Host != nil && t.UsedBy != id {
			return fmt.Errorf("host token must be consumed by this host")
		}
		if r.Host == nil && t.UsedBy != "" && !t.Revoked {
			return fmt.Errorf("historical consumed token must be revoked")
		}
	}
	if h := r.Host; h != nil {
		if h.Revision == 0 {
			return fmt.Errorf("invalid host metadata")
		}
		if err := h.Proposal.Validate(); err != nil {
			return err
		}
		switch h.Status {
		case "pending", "approved", "denied", "removed":
		default:
			return fmt.Errorf("unknown host status %q", h.Status)
		}
		for i, name := range h.RetiredNames {
			normalized, err := normalizeRetiredName(name)
			if err != nil {
				return err
			}
			h.RetiredNames[i] = normalized
		}
	}
	return nil
}
func normalizeRetiredName(name string) (string, error) {
	name = hostpattern.NormalizeName(name)
	p := Proposal{Names: []string{name}, PrincipalMode: AccountNamePrincipals}
	return name, p.Validate()
}

// Only v1 migration needs this file: the old snapshot did not associate retired
// names with their original host, and may contain audit for historical resources.
type legacyMetadata struct {
	Version      int          `yaml:"version"`
	RetiredNames []string     `yaml:"retired-names,omitempty"`
	Audit        []AuditEvent `yaml:"audit,omitempty"`
}

type itemFiles struct {
	root        string
	dir         string
	lock        *os.File
	newID       func() (string, error)
	writeAtomic func(string, []byte, bool) error
}

func (f *itemFiles) Close() error              { return f.lock.Close() }
func (f *itemFiles) itemPath(id string) string { return filepath.Join(f.dir, id+".yaml") }
func (f *itemFiles) write(r *itemRecord, create bool) error {
	if err := r.validate(r.id()); err != nil {
		return err
	}
	data, err := yaml.Marshal(r)
	if err != nil {
		return err
	}
	return f.writeAtomic(f.itemPath(r.id()), data, create)
}

// atomicItemWrite publishes a fully written, synced temporary file. A hard link
// reserves a new filename exclusively without exposing a partially written item.
// Replacements use rename so token redemption is exactly one atomic transition.
func atomicItemWrite(path string, data []byte, create bool) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".item-*")
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
	if create {
		if err = os.Link(f.Name(), path); errors.Is(err, os.ErrExist) {
			return errItemExists
		} else if err != nil {
			return err
		}
		if err = os.Remove(f.Name()); err != nil {
			return err
		}
	} else if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncManagedDir(dir)
}

func OpenManaged(dir string, static *Static) (*Managed, error) {
	return openManaged(dir, static, false)
}

// OpenManagedAllowDegraded permits startup with unreadable dynamic state.
// Exact static records always override dynamic records, including in this mode.
// Wildcards cannot be used when unreadable state may contain admission tombstones.
func OpenManagedAllowDegraded(dir string, static *Static) (*Managed, error) {
	return openManaged(dir, static, true)
}
func openManaged(dir string, static *Static, allowDegraded bool) (*Managed, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "inventory.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockManagedFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("inventory state is already in use: %w", err)
	}
	files := &itemFiles{root: dir, dir: filepath.Join(dir, "records"), lock: lock, newID: RandomSecret, writeAtomic: atomicItemWrite}
	m := newManaged(files, static)
	if err = m.prepareFiles(); err == nil {
		err = m.load(files.dir)
	}
	if err != nil {
		if allowDegraded {
			m = newManaged(files, static)
			m.failed = fmt.Errorf("%w: %v", ErrStorage, err)
			return m, nil
		}
		lock.Close()
		return nil, fmt.Errorf("opening managed inventory: %w", err)
	}
	return m, nil
}
func newManaged(files *itemFiles, static *Static) *Managed {
	m := &Managed{files: files, records: map[string]*itemRecord{}, names: map[string]*nameClaims{}, domains: map[string]string{}, staticDomains: map[string]bool{}, hashes: map[string]string{}, static: static, legacy: legacyMetadata{Version: 2}}
	if static != nil {
		for _, h := range static.hosts {
			if h.Domain != "" {
				m.staticDomains[string(h.Domain)] = true
			}
		}
	}
	return m
}
func (m *Managed) load(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	// ReadDir sorts filenames. Startup diagnostics and migration output are stable.
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".item-") {
			continue
		} // interrupted temporary writes are not records
		if !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s: inventory items must be regular files", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		if entry.Name() == "legacy.yaml" {
			if err := DecodeYAML(data, &m.legacy); err != nil {
				return fmt.Errorf("legacy.yaml: %w", err)
			}
			if m.legacy.Version != 2 {
				return fmt.Errorf("unsupported legacy metadata version")
			}
			for i, name := range m.legacy.RetiredNames {
				normalized, err := normalizeRetiredName(name)
				if err != nil {
					return err
				}
				m.legacy.RetiredNames[i] = normalized
			}
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".yaml")
		var r itemRecord
		if err := DecodeYAML(data, &r); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if err := r.validate(id); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if err := m.checkIndexes(&r); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		m.publish(&r)
	}
	for _, n := range m.legacy.RetiredNames {
		entry := m.names[n]
		if entry == nil {
			entry = &nameClaims{owners: map[string]struct{}{}}
			m.names[n] = entry
		}
		entry.owners["legacy"] = struct{}{}
	}
	m.updateRevision()
	return nil
}

// Indexed get is useful to API callers that already have a stable record ID.
func (m *Managed) Get(id string) (*HostRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failed != nil {
		return nil, m.failed
	}
	if m.static != nil && strings.HasPrefix(id, "static") {
		for _, h := range m.static.Records() {
			if h.ID == id {
				return &h, nil
			}
		}
	}
	r := m.records[id]
	if r == nil || r.Host == nil {
		return nil, ErrNotFound
	}
	h := cloneHost(r.Host)
	h.Source = "dynamic"
	h.SourceFile = m.files.itemPath(id)
	if m.static != nil {
		for _, n := range h.Proposal.Names {
			if m.static.hosts[n] != nil {
				h.ShadowedNames = append(h.ShadowedNames, n)
			}
		}
	}
	return h, nil
}

// Sort helper used by migration to produce deterministic files.
func sortedItemIDs(records map[string]*itemRecord) []string {
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
