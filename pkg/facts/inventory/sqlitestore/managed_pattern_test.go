package sqlitestore

import (
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func patternProposal(pattern string) inventory.Proposal {
	return inventory.Proposal{Pattern: pattern, Accounts: []string{"root"}, Labels: map[string]string{"role": "runner"}, PrincipalMode: inventory.AccountNamePrincipals}
}

func TestManagedPatternResolutionAndLifecycle(t *testing.T) {
	m, path := managedFixture(t, "")
	pattern, err := m.AddPattern(t.Context(), "admin", patternProposal("Runner-*.EXAMPLE"))
	require.NoError(t, err)
	require.Equal(t, "runner-*.example", pattern.Proposal.Pattern)
	require.Equal(t, "active", pattern.Status)
	for _, name := range []string{"runner-one.example", "RUNNER-TWO.EXAMPLE"} {
		h, _, err := m.LookupHost(t.Context(), name)
		require.NoError(t, err)
		require.Equal(t, []string{strings.ToLower(name)}, h.Policy.Names)
		require.Equal(t, pattern.Proposal.Accounts, h.Policy.Accounts)
		require.Equal(t, pattern.Proposal.Labels, h.Policy.Labels)
	}
	h, _, err := m.LookupHost(t.Context(), "runner-one.sub.example")
	require.NoError(t, err)
	require.Nil(t, h)

	// Pending exact records leave the fleet rule in effect.
	exact, err := m.Enroll(t.Context(), proposal("runner-one.example"), "")
	require.NoError(t, err)
	h, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts)
	exact, err = m.Change(t.Context(), "admin", "approve", exact.ID, exact.Revision, nil)
	require.NoError(t, err)
	h, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Policy.Accounts)
	_, err = m.Change(t.Context(), "admin", "remove", exact.ID, exact.Revision, nil)
	require.NoError(t, err)
	h, before, err := m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts)

	updated := patternProposal("worker-**.example")
	_, err = m.Change(t.Context(), "admin", "edit", pattern.ID, pattern.Revision, &updated)
	require.Error(t, err)
	updated.Pattern = "worker-*.example"
	pattern, err = m.Change(t.Context(), "admin", "edit", pattern.ID, pattern.Revision, &updated)
	require.NoError(t, err)
	h, after, err := m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Nil(t, h)
	require.NotEqual(t, before, after)
	require.NoError(t, m.Close())
	restarted, err := Open(path)
	require.NoError(t, err)
	defer restarted.Close()
	record, err := restarted.Get(t.Context(), pattern.ID)
	require.NoError(t, err)
	require.Equal(t, pattern, record)
	h, _, err = restarted.LookupHost(t.Context(), "worker-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"worker-one.example"}, h.Policy.Names)
	_, err = restarted.Change(t.Context(), "admin", "remove", pattern.ID, pattern.Revision, nil)
	require.NoError(t, err)
	h, _, err = restarted.LookupHost(t.Context(), "worker-one.example")
	require.NoError(t, err)
	require.Nil(t, h)
}

func TestManagedAmbiguousPatternsFailUntilDisambiguated(t *testing.T) {
	m, _ := managedFixture(t, "")
	first, err := m.AddPattern(t.Context(), "admin", patternProposal("*.example"))
	require.NoError(t, err)
	second, err := m.Enroll(t.Context(), patternProposal("runner-*.*"), "")
	require.NoError(t, err)
	_, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err, "pending patterns are inert")
	second, err = m.Change(t.Context(), "admin", "approve", second.ID, second.Revision, nil)
	require.NoError(t, err)
	_, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.ErrorIs(t, err, inventory.ErrConflict)
	// An exact record resolves the name even when patterns overlap.
	exact, err := m.Enroll(t.Context(), proposal("runner-one.example"), "")
	require.NoError(t, err)
	exact, err = m.Change(t.Context(), "admin", "approve", exact.ID, exact.Revision, nil)
	require.NoError(t, err)
	h, _, err := m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Policy.Accounts)
	_, err = m.Change(t.Context(), "admin", "remove", exact.ID, exact.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "remove", first.ID, first.Revision, nil)
	require.NoError(t, err)
	_, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	_, err = m.AddPattern(t.Context(), "admin", patternProposal(second.Proposal.Pattern))
	require.ErrorIs(t, err, inventory.ErrConflict)
}

func TestManagedPatternValidationAndCreationRollback(t *testing.T) {
	m, _ := managedFixture(t, "")
	for _, p := range []inventory.Proposal{
		proposal("exact"),
		{Names: []string{"exact"}, Pattern: "*", PrincipalMode: inventory.AccountNamePrincipals},
		patternProposal("bad-**.example"),
		{Pattern: "*.example", PrincipalMode: inventory.EpithetPrincipalV1, Realm: "epithet-host-id-v1:" + strings.Repeat("A", 43)},
	} {
		_, err := m.AddPattern(t.Context(), "admin", p)
		require.Error(t, err)
	}
	_, before, err := m.LookupHost(t.Context(), "host.example")
	require.NoError(t, err)
	_, err = m.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'simulated failure'); END")
	require.NoError(t, err)
	_, err = m.AddPattern(t.Context(), "admin", patternProposal("*.example"))
	require.ErrorIs(t, err, inventory.ErrStorage)
	records, err := m.List(t.Context(), "", 0, false)
	require.NoError(t, err)
	require.Empty(t, records)
	events, err := m.Audit(t.Context(), 0, 0)
	require.NoError(t, err)
	require.Empty(t, events)
	_, after, err := m.LookupHost(t.Context(), "host.example")
	require.NoError(t, err)
	require.Equal(t, before, after)
}
