package sqlitestore

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	require.Equal(t, 1, version)
	_, err = m.db.Exec("PRAGMA user_version=99")
	require.NoError(t, err)
	require.NoError(t, m.Close())
	_, err = Open(path)
	require.ErrorContains(t, err, "unsupported inventory database version 99")
}

func TestManagedTokenRedemptionRollsBackAllState(t *testing.T) {
	m, path := managedFixture(t, "")
	token, err := m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	before, err := m.Get(t.Context(), token.ID)
	require.NoError(t, err)
	auditBefore, err := m.Audit(t.Context())
	require.NoError(t, err)
	_, revisionBefore, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	// Audit is written after the host, collections, and token. Failing here
	// must undo the entire redemption, not just the audit insert.
	_, err = m.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END")
	require.NoError(t, err)
	_, err = m.Enroll(t.Context(), proposal("host"), token.ID)
	require.ErrorIs(t, err, inventory.ErrStorage)
	_, err = m.db.Exec("DROP TRIGGER fail_audit")
	require.NoError(t, err)
	require.NoError(t, m.Close())
	restarted, err := Open(path)
	require.NoError(t, err)
	defer restarted.Close()
	current, err := restarted.Get(t.Context(), token.ID)
	require.NoError(t, err)
	require.Equal(t, before, current)
	tokens, err := restarted.Tokens(t.Context())
	require.NoError(t, err)
	require.Equal(t, []inventory.EnrollmentToken{token}, tokens)
	auditAfter, err := restarted.Audit(t.Context())
	require.NoError(t, err)
	require.Equal(t, auditBefore, auditAfter)
	got, revisionAfter, err := restarted.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.Nil(t, got)
	require.Equal(t, revisionBefore, revisionAfter)
	h, err := restarted.Enroll(t.Context(), proposal("host"), token.ID)
	require.NoError(t, err)
	require.Equal(t, token.ID, h.ID)
	require.Equal(t, "active", h.Status)
}

func TestManagedRemovalRollsBackAndCascades(t *testing.T) {
	m, _ := managedFixture(t, "")
	token, err := m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	p := proposal("host")
	p.Names = []string{"host", "alias"}
	p.Labels = map[string]string{"env": "test"}
	h, err := m.Enroll(t.Context(), p, token.ID)
	require.NoError(t, err)
	auditBefore, err := m.Audit(t.Context())
	require.NoError(t, err)
	_, revisionBefore, err := m.LookupHost(t.Context(), "alias")
	require.NoError(t, err)
	_, err = m.db.Exec("CREATE TRIGGER fail_remove BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "remove", h.ID, h.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrStorage)
	got, revisionAfter, err := m.LookupHost(t.Context(), "alias")
	require.NoError(t, err)
	require.Equal(t, h.Proposal.Names, got.Policy.Names)
	require.Equal(t, h.Proposal.Labels, got.Policy.Labels)
	require.Equal(t, h.Proposal.Accounts, got.Policy.Accounts)
	require.Equal(t, revisionBefore, revisionAfter)
	auditAfter, err := m.Audit(t.Context())
	require.NoError(t, err)
	require.Equal(t, auditBefore, auditAfter)
	tokens, err := m.Tokens(t.Context())
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	require.Equal(t, h.ID, tokens[0].UsedBy)
	_, err = m.db.Exec("DROP TRIGGER fail_remove")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "remove", h.ID, h.Revision, nil)
	require.NoError(t, err)
	for _, table := range []string{"hosts", "names", "labels", "accounts", "tokens", "audit"} {
		var count int
		require.NoError(t, m.db.QueryRow("SELECT count(*) FROM "+table).Scan(&count))
		require.Zero(t, count, table)
	}
}

func TestManagedConnectionsReadCurrentStateAndStableRevision(t *testing.T) {
	m, path := managedFixture(t, "hosts:\n - pattern: '*'\n   accounts: [root]\n")
	other, err := Open(path)
	require.NoError(t, err)
	defer other.Close()
	h, err := m.Enroll(t.Context(), proposal("old"), "")
	require.NoError(t, err)
	h, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	got, revision, err := other.LookupHost(t.Context(), "OLD")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, got.Policy.Accounts)
	p := proposal("current")
	h, err = m.Change(t.Context(), "admin", "edit", h.ID, h.Revision, &p)
	require.NoError(t, err)
	_, err = other.Change(t.Context(), "admin", "remove", h.ID, h.Revision-1, nil)
	require.ErrorIs(t, err, inventory.ErrRevision)
	old, _, err := other.LookupHost(t.Context(), "old")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, old.Policy.Accounts)
	got, updatedRevision, err := other.LookupHost(t.Context(), "current")
	require.NoError(t, err)
	require.Equal(t, []string{"current"}, got.Policy.Names)
	require.NotEqual(t, revision, updatedRevision)
	require.NoError(t, other.Close())
	require.NoError(t, m.Close())
	restarted, err := Open(path)
	require.NoError(t, err)
	defer restarted.Close()
	_, stableRevision, err := restarted.LookupHost(t.Context(), "current")
	require.NoError(t, err)
	require.Equal(t, updatedRevision, stableRevision)
}

func TestManagedReadSnapshotDoesNotMixHostAndRevision(t *testing.T) {
	m, path := managedFixture(t, "")
	other, err := Open(path)
	require.NoError(t, err)
	defer other.Close()
	h, err := m.Enroll(t.Context(), proposal("host"), "")
	require.NoError(t, err)
	h, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	tx, err := m.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	defer tx.Rollback()
	beforeRevision, err := inventoryRevision(t.Context(), tx)
	require.NoError(t, err)
	p := proposal("host")
	p.Accounts = nil
	_, err = other.Change(t.Context(), "admin", "edit", h.ID, h.Revision, &p)
	require.NoError(t, err)
	before, err := readHost(t.Context(), tx, h.ID)
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, before.Proposal.Accounts)
	revision, err := inventoryRevision(t.Context(), tx)
	require.NoError(t, err)
	require.Equal(t, beforeRevision, revision)
	require.NoError(t, tx.Commit())
	after, afterRevision, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.Nil(t, after.Policy.Accounts)
	require.NotEqual(t, beforeRevision, afterRevision)
}

func TestManagedIDCollisionDoesNotOverwriteHost(t *testing.T) {
	m, _ := managedFixture(t, "")
	original, err := m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	next := strings.Repeat("a", 64)
	call := 0
	m.newID = func() (string, error) {
		call++
		if call == 1 {
			return original.ID, nil
		}
		return next, nil
	}
	token, err := m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	require.Equal(t, next, token.ID)
	require.Equal(t, 2, call)
	tokens, err := m.Tokens(t.Context())
	require.NoError(t, err)
	require.Contains(t, tokens, original)
}

func TestManagedStartupValidatesRecords(t *testing.T) {
	m, path := managedFixture(t, "hosts:\n - names: [static]\n   accounts: [root]\n")
	h, err := m.Enroll(t.Context(), proposal("host"), "")
	require.NoError(t, err)
	_, err = m.db.Exec("UPDATE hosts SET principal_mode='invalid' WHERE id=?", h.ID)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	_, err = Open(path)
	require.ErrorContains(t, err, "unknown principal mode")
}

func TestCanceledOperationsLeaveInventoryUnchanged(t *testing.T) {
	m, _ := managedFixture(t, "")
	host, err := m.Enroll(t.Context(), proposal("host"), "")
	require.NoError(t, err)
	token, err := m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	records, err := m.List(t.Context())
	require.NoError(t, err)
	audit, err := m.Audit(t.Context())
	require.NoError(t, err)
	_, revision, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"enroll", func() error { _, err := m.Enroll(ctx, proposal("new"), ""); return err }},
		{"add-pattern", func() error { _, err := m.AddPattern(ctx, "admin", patternProposal("*.example")); return err }},
		{"approve", func() error { _, err := m.Change(ctx, "admin", "approve", host.ID, host.Revision, nil); return err }},
		{"get", func() error { _, err := m.Get(ctx, host.ID); return err }},
		{"list", func() error { _, err := m.List(ctx); return err }},
		{"create-token", func() error { _, err := m.CreateToken(ctx, "admin", time.Hour); return err }},
		{"tokens", func() error { _, err := m.Tokens(ctx); return err }},
		{"revoke-token", func() error { return m.RevokeToken(ctx, "admin", token.ID) }},
		{"audit", func() error { _, err := m.Audit(ctx); return err }},
		{"lookup", func() error { _, _, err := m.LookupHost(ctx, "host"); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			require.ErrorIs(t, err, context.Canceled)
			require.ErrorIs(t, err, inventory.ErrStorage)
		})
	}
	after, err := m.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, records, after)
	auditAfter, err := m.Audit(t.Context())
	require.NoError(t, err)
	require.Equal(t, audit, auditAfter)
	_, revisionAfter, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.Equal(t, revision, revisionAfter)
	tokens, err := m.Tokens(t.Context())
	require.NoError(t, err)
	require.Equal(t, []inventory.EnrollmentToken{token}, tokens)
}
