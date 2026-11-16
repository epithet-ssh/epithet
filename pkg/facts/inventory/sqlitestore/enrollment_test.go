package sqlitestore

import (
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEnrollmentRetriesAfterRestart(t *testing.T) {
	m, path := managedFixture(t, "")
	id := inventory.NewID()
	h, err := inventory.CreateHost(t.Context(), m, id, proposal("retry.example"), inventory.NewAuditEvent("provisioner", "enroll", id))
	require.NoError(t, err)
	require.Equal(t, inventory.StatusActive, h.Status)
	events, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	fresh, err := Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	retry, err := inventory.CreateHost(t.Context(), fresh, id, proposal("retry.example"), inventory.NewAuditEvent("another-provisioner", "enroll", id))
	require.NoError(t, err)
	require.Equal(t, h, retry)
	_, err = inventory.CreateHost(t.Context(), fresh, id, proposal("changed.example"), inventory.NewAuditEvent("provisioner", "enroll", id))
	require.ErrorIs(t, err, inventory.ErrConflict)
	after, _, err := fresh.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, events, after)
	edited := proposal("edited.example")
	current, err := fresh.Change(t.Context(), "admin", "edit", id, h.Version, &edited)
	require.NoError(t, err)
	_, err = inventory.CreateHost(t.Context(), fresh, id, proposal("retry.example"), inventory.NewAuditEvent("provisioner", "enroll", id))
	require.ErrorIs(t, err, inventory.ErrConflict, "enrollment cannot undo an administrator edit")
	stored, err := fresh.GetHost(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, current, stored)
}

func TestRetireCredentialTablePreservesActiveHosts(t *testing.T) {
	m, path := managedFixture(t, "hosts:\n - names: [existing.example]\n   accounts: [root]\n")
	before, err := m.ListHosts(t.Context(), "", 0)
	require.NoError(t, err)
	audit, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	// Recreate the previous credential table/version around existing active data.
	_, err = m.db.Exec(`CREATE TABLE tokens (host_id TEXT PRIMARY KEY, expires TEXT NOT NULL, used INTEGER NOT NULL, revoked INTEGER NOT NULL); INSERT INTO tokens VALUES ('old-credential','2099-01-01T00:00:00Z',0,0); PRAGMA user_version=5;`)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	fresh, err := Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	after, err := fresh.ListHosts(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, before, after)
	events, _, err := fresh.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, audit, events)
	host, err := fresh.LookupHost(t.Context(), "existing.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, host.Accounts)
	var tables int
	require.NoError(t, fresh.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='tokens'").Scan(&tables))
	require.Zero(t, tables)
}
