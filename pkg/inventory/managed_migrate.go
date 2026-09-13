package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// v1 persisted hashes instead of literal token IDs; those secrets cannot be
// recovered. Migration preserves the metadata but revokes all legacy tokens.
type legacyToken struct {
	EnrollmentToken `yaml:",inline"`
	Hash            string `yaml:"hash"`
}
type legacyState struct {
	Version      int           `yaml:"version"`
	Revision     uint64        `yaml:"revision"`
	Hosts        []HostRecord  `yaml:"hosts"`
	Tokens       []legacyToken `yaml:"tokens"`
	BlockedNames []string      `yaml:"blocked-names"`
	Audit        []AuditEvent  `yaml:"audit"`
}

func (m *Managed) prepareFiles() error {
	if info, err := os.Stat(m.files.dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("records must be a directory")
		}
		return m.archiveLegacy() // finish a cutover interrupted after directory rename
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	oldPath := filepath.Join(m.files.root, "inventory.yaml")
	data, err := os.ReadFile(oldPath)
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Stat(filepath.Join(m.files.root, "inventory.v1.yaml.bak")); e == nil {
			return fmt.Errorf("records directory is missing beside a migrated backup; restore records instead of resetting admission")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if err := os.Mkdir(m.files.dir, 0700); err != nil {
			return err
		}
		return syncManagedDir(m.files.root)
	}
	if err != nil {
		return err
	}
	var old legacyState
	if err := DecodeYAML(data, &old); err != nil {
		return err
	}
	if old.Version != 1 {
		return fmt.Errorf("unsupported state version %d", old.Version)
	}
	records := map[string]*itemRecord{}
	for i := range old.Hosts {
		h := cloneHost(&old.Hosts[i])
		if records[h.ID] != nil {
			return fmt.Errorf("duplicate legacy host ID %q", h.ID)
		}
		records[h.ID] = &itemRecord{Version: 2, Kind: "host", Host: h}
	}
	for _, t := range old.Tokens {
		if records[t.ID] != nil {
			return fmt.Errorf("duplicate legacy item ID %q", t.ID)
		}
		token := t.EnrollmentToken
		token.Revoked = true
		records[t.ID] = &itemRecord{Version: 2, Kind: "token", Token: &token}
	}
	legacy := legacyMetadata{Version: 2, RetiredNames: old.BlockedNames}
	for _, e := range old.Audit {
		if r := records[e.Resource]; r != nil {
			r.Audit = append(r.Audit, e)
		} else {
			legacy.Audit = append(legacy.Audit, e)
		}
	}
	stage, err := os.MkdirTemp(m.files.root, ".records-migration-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, id := range sortedItemIDs(records) {
		r := records[id]
		if err := r.validate(id); err != nil {
			return fmt.Errorf("legacy item %s: %w", id, err)
		}
		data, err := yaml.Marshal(r)
		if err != nil {
			return err
		}
		if err := atomicItemWrite(filepath.Join(stage, id+".yaml"), data, true); err != nil {
			return err
		}
	}
	if len(legacy.RetiredNames) > 0 || len(legacy.Audit) > 0 {
		data, err := yaml.Marshal(legacy)
		if err != nil {
			return err
		}
		if err := atomicItemWrite(filepath.Join(stage, "legacy.yaml"), data, true); err != nil {
			return err
		}
	}
	// Validate the entire index before publishing migration. Duplicate approved
	// names never produce an arbitrarily selected active host.
	check := newManaged(m.files, m.static)
	if err := check.load(stage); err != nil {
		return err
	}
	if err := syncManagedDir(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, m.files.dir); err != nil {
		return err
	}
	if err := syncManagedDir(m.files.root); err != nil {
		return err
	}
	return m.archiveLegacy()
}
func (m *Managed) archiveLegacy() error {
	old := filepath.Join(m.files.root, "inventory.yaml")
	if _, err := os.Stat(old); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	backup := filepath.Join(m.files.root, "inventory.v1.yaml.bak")
	// Never replace a backup; an interrupted link/unlink is safe to finish only
	// when both paths name the original file.
	if err := os.Link(old, backup); errors.Is(err, os.ErrExist) {
		a, e := os.Stat(old)
		if e != nil {
			return e
		}
		b, e := os.Stat(backup)
		if e != nil {
			return e
		}
		if !os.SameFile(a, b) {
			return fmt.Errorf("legacy snapshot and migration backup both exist; retain the records directory and resolve the backup conflict")
		}
	} else if err != nil {
		return err
	}
	if err := os.Remove(old); err != nil {
		return err
	}
	return syncManagedDir(m.files.root)
}
