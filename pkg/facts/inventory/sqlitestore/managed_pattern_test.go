package sqlitestore

import (
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func patternInput(pattern string) inventory.Host {
	return inventory.Host{Status: inventory.StatusActive, Names: []string{pattern}, Accounts: []string{"root"}, Labels: map[string]string{"role": "runner"}, PrincipalMode: inventory.AccountNamePrincipals}
}

func TestManagedPatternResolutionAndLifecycle(t *testing.T) {
	m, path := managedFixture(t, "")
	id1 := inventory.NewID()
	input1 := patternInput("Runner-*.EXAMPLE")
	input1.ID = id1
	pattern, err := m.UpsertHost(t.Context(), input1, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id1))
	require.NoError(t, err)
	require.Equal(t, "runner-*.example", pattern.Names[0])
	for _, name := range []string{"runner-one.example", "RUNNER-TWO.EXAMPLE"} {
		h, err := m.LookupHost(t.Context(), name)
		require.NoError(t, err)
		require.Equal(t, []string{strings.ToLower(name)}, h.Names)
		require.Equal(t, pattern.Accounts, h.Accounts)
		require.Equal(t, pattern.Labels, h.Labels)
	}
	h, err := m.LookupHost(t.Context(), "runner-one.sub.example")
	require.NoError(t, err)
	require.Nil(t, h)

	// Pending exact records leave the fleet rule in effect.
	id2 := inventory.NewID()
	exact, err := inventory.Enroll(t.Context(), m, id2, proposal("runner-one.example"), "", inventory.NewAuditEvent("host", "enroll", id2))
	require.NoError(t, err)
	h, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Accounts)
	exact, err = m.Change(t.Context(), "admin", "approve", exact.ID, exact.Version, nil)
	require.NoError(t, err)
	h, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Accounts)
	_, err = m.Change(t.Context(), "admin", "remove", exact.ID, exact.Version, nil)
	require.NoError(t, err)
	h, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Accounts)

	updated := patternInput("worker-**.example")
	_, err = m.Change(t.Context(), "admin", "edit", pattern.ID, pattern.Version, &updated)
	require.Error(t, err)
	updated.Names[0] = "worker-*.example"
	pattern, err = m.Change(t.Context(), "admin", "edit", pattern.ID, pattern.Version, &updated)
	require.NoError(t, err)
	h, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Nil(t, h)
	require.NoError(t, m.Close())
	restarted, err := Open(path)
	require.NoError(t, err)
	defer restarted.Close()
	record, err := restarted.GetHost(t.Context(), pattern.ID)
	require.NoError(t, err)
	require.Equal(t, pattern, record)
	h, err = restarted.LookupHost(t.Context(), "worker-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"worker-one.example"}, h.Names)
	_, err = restarted.Change(t.Context(), "admin", "remove", pattern.ID, pattern.Version, nil)
	require.NoError(t, err)
	h, err = restarted.LookupHost(t.Context(), "worker-one.example")
	require.NoError(t, err)
	require.Nil(t, h)
}

func TestManagedAmbiguousPatternsFailUntilDisambiguated(t *testing.T) {
	m, _ := managedFixture(t, "")
	id3 := inventory.NewID()
	input2 := patternInput("*.example")
	input2.ID = id3
	first, err := m.UpsertHost(t.Context(), input2, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id3))
	require.NoError(t, err)
	id4 := inventory.NewID()
	input3 := patternInput("runner-*.*")
	input3.ID = id4
	second, err := m.UpsertHost(t.Context(), input3, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id4))
	require.NoError(t, err)
	_, err = m.LookupHost(t.Context(), "runner-one.example")
	require.ErrorIs(t, err, inventory.ErrConflict)
	// An exact record resolves the name even when patterns overlap.
	id5 := inventory.NewID()
	exact, err := inventory.Enroll(t.Context(), m, id5, proposal("runner-one.example"), "", inventory.NewAuditEvent("host", "enroll", id5))
	require.NoError(t, err)
	exact, err = m.Change(t.Context(), "admin", "approve", exact.ID, exact.Version, nil)
	require.NoError(t, err)
	h, err := m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Accounts)
	_, err = m.Change(t.Context(), "admin", "remove", exact.ID, exact.Version, nil)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "remove", first.ID, first.Version, nil)
	require.NoError(t, err)
	_, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	id6 := inventory.NewID()
	input4 := patternInput(second.Names[0])
	input4.ID = id6
	_, err = m.UpsertHost(t.Context(), input4, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id6))
	require.ErrorIs(t, err, inventory.ErrConflict)
}

func TestManagedPatternValidationAndCreationRollback(t *testing.T) {
	m, _ := managedFixture(t, "")
	for _, p := range []inventory.Host{
		{Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals},
		patternInput("bad-**.example"),
	} {
		id7 := inventory.NewID()
		p.ID = id7
		_, err := m.UpsertHost(t.Context(), p, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id7))
		require.Error(t, err)
	}
	_, err := m.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'simulated failure'); END")
	require.NoError(t, err)
	id8 := inventory.NewID()
	input5 := patternInput("*.example")
	input5.ID = id8
	_, err = m.UpsertHost(t.Context(), input5, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id8))
	require.ErrorIs(t, err, inventory.ErrStorage)
	records, err := m.ListHosts(t.Context(), "", 0, false)
	require.NoError(t, err)
	require.Empty(t, records)
	events, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Empty(t, events)
}
