package sqlitestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func TestManagedSQLitePermissionsAndSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory", "inventory.db")
	m, err := Open(path)
	require.NoError(t, err)
	defer m.Close()
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{{path, 0600}, {filepath.Dir(path), 0700}} {
		info, err := os.Stat(entry.path)
		require.NoError(t, err)
		require.Equal(t, entry.mode, info.Mode().Perm())
	}
	var version int
	require.NoError(t, m.db.QueryRow("PRAGMA user_version").Scan(&version))
	require.Equal(t, 6, version)
	_, err = m.db.Exec("PRAGMA user_version=99")
	require.NoError(t, err)
	require.NoError(t, m.Close())
	_, err = Open(path)
	require.ErrorContains(t, err, "unsupported inventory database version 99")
}

func TestManagedRejectsSchemaWithCascadingAuditDeletion(t *testing.T) {
	m, path := managedFixture(t, "")
	_, err := m.db.Exec("PRAGMA user_version=1")
	require.NoError(t, err)
	require.NoError(t, m.Close())
	_, err = Open(path)
	require.ErrorContains(t, err, "unsupported inventory database version 1")
}

func TestManagedCreationRollsBackAllState(t *testing.T) {
	m, path := managedFixture(t, "")
	id1 := inventory.NewID()
	auditBefore, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	// Audit is written after the host and collections. Failing here
	// must undo the entire creation, not just the audit insert.
	_, err = m.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END")
	require.NoError(t, err)
	id2 := id1
	_, err = inventory.CreateHost(t.Context(), m, id2, proposal("host"), inventory.NewAuditEvent("host", "enroll", id2))
	require.ErrorIs(t, err, inventory.ErrStorage)
	_, err = m.db.Exec("DROP TRIGGER fail_audit")
	require.NoError(t, err)
	require.NoError(t, m.Close())
	restarted, err := Open(path)
	require.NoError(t, err)
	defer restarted.Close()
	_, err = restarted.GetHost(t.Context(), id1)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	auditAfter, _, err := restarted.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, auditBefore, auditAfter)
	got, err := restarted.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.Nil(t, got)
	id3 := id1
	h, err := inventory.CreateHost(t.Context(), restarted, id3, proposal("host"), inventory.NewAuditEvent("host", "enroll", id3))
	require.NoError(t, err)
	require.Equal(t, id1, h.ID)
	require.Equal(t, "active", h.Status)
}

func TestManagedRemovalRollsBackAndCascades(t *testing.T) {
	m, _ := managedFixture(t, "")
	p := proposal("host")
	p.Names = []string{"host", "alias"}
	p.Labels = map[string]string{"env": "test"}
	id5 := inventory.NewID()
	h, err := inventory.CreateHost(t.Context(), m, id5, p, inventory.NewAuditEvent("host", "enroll", id5))
	require.NoError(t, err)
	auditBefore, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	_, err = m.db.Exec("CREATE TRIGGER fail_remove BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "remove", h.ID, h.Version, nil)
	require.ErrorIs(t, err, inventory.ErrStorage)
	got, err := m.LookupHost(t.Context(), "alias")
	require.NoError(t, err)
	require.Equal(t, h.Names, got.Names)
	require.Equal(t, h.Labels, got.Labels)
	require.Equal(t, h.Accounts, got.Accounts)
	auditAfter, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, auditBefore, auditAfter)
	_, err = m.db.Exec("DROP TRIGGER fail_remove")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "remove", h.ID, h.Version, nil)
	require.NoError(t, err)
	for _, table := range []string{"hosts", "names", "labels", "accounts"} {
		var count int
		require.NoError(t, m.db.QueryRow("SELECT count(*) FROM "+table).Scan(&count))
		require.Zero(t, count, table)
	}
}

func TestManagedConnectionsReadCurrentState(t *testing.T) {
	m, path := managedFixture(t, "hosts:\n - names: ['*']\n   accounts: [root]\n")
	other, err := Open(path)
	require.NoError(t, err)
	defer other.Close()
	id6 := inventory.NewID()
	h, err := inventory.CreateHost(t.Context(), m, id6, proposal("old"), inventory.NewAuditEvent("host", "enroll", id6))
	require.NoError(t, err)
	got, err := other.LookupHost(t.Context(), "OLD")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, got.Accounts)
	previousVersion := h.Version
	p := proposal("current")
	h, err = m.Change(t.Context(), "admin", "edit", h.ID, h.Version, &p)
	require.NoError(t, err)
	_, err = other.Change(t.Context(), "admin", "remove", h.ID, previousVersion, nil)
	require.ErrorIs(t, err, inventory.ErrVersion)
	old, err := other.LookupHost(t.Context(), "old")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, old.Accounts)
	got, err = other.LookupHost(t.Context(), "current")
	require.NoError(t, err)
	require.Equal(t, []string{"current"}, got.Names)
	require.NoError(t, other.Close())
	require.NoError(t, m.Close())
	restarted, err := Open(path)
	require.NoError(t, err)
	defer restarted.Close()
	got, err = restarted.LookupHost(t.Context(), "current")
	require.NoError(t, err)
	require.Equal(t, []string{"current"}, got.Names)
}

func TestManagedStartupValidatesRecords(t *testing.T) {
	m, path := managedFixture(t, "hosts:\n - names: [static]\n   accounts: [root]\n")
	id10 := inventory.NewID()
	h, err := inventory.CreateHost(t.Context(), m, id10, proposal("host"), inventory.NewAuditEvent("host", "enroll", id10))
	require.NoError(t, err)
	_, err = m.db.Exec("UPDATE hosts SET principal_mode='invalid' WHERE id=?", h.ID)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	_, err = Open(path)
	require.ErrorContains(t, err, "unknown principal mode")
}

func TestCanceledOperationsLeaveInventoryUnchanged(t *testing.T) {
	m, _ := managedFixture(t, "")
	id11 := inventory.NewID()
	host, err := inventory.CreateHost(t.Context(), m, id11, proposal("host"), inventory.NewAuditEvent("host", "enroll", id11))
	require.NoError(t, err)
	records, err := m.ListHosts(t.Context(), "", 0)
	require.NoError(t, err)
	audit, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"enroll", func() error {
			id13 := inventory.NewID()
			_, err := inventory.CreateHost(ctx, m, id13, proposal("new"), inventory.NewAuditEvent("host", "enroll", id13))
			return err
		}},
		{"add", func() error {
			id14 := inventory.NewID()
			input1 := patternInput("*.example")
			input1.ID = id14
			_, err := m.UpsertHost(ctx, input1, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id14))
			return err
		}},
		{"edit", func() error { _, err := m.Change(ctx, "admin", "edit", host.ID, host.Version, nil); return err }},
		{"get", func() error { _, err := m.GetHost(ctx, host.ID); return err }},
		{"list", func() error { _, err := m.ListHosts(ctx, "", 0); return err }},
		{"audit", func() error { _, _, err := m.Audit(ctx, "", 0); return err }},
		{"lookup", func() error { _, err := m.LookupHost(ctx, "host"); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			require.ErrorIs(t, err, context.Canceled)
			require.ErrorIs(t, err, inventory.ErrStorage)
		})
	}
	after, err := m.ListHosts(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, records, after)
	auditAfter, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, audit, auditAfter)
}
