package inventory

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func patternProposal(pattern string) Proposal {
	return Proposal{Pattern: pattern, Accounts: []string{"root"}, Labels: map[string]string{"role": "runner"}, PrincipalMode: AccountNamePrincipals}
}

func TestManagedPatternResolutionAndLifecycle(t *testing.T) {
	m, path := managedFixture(t, "")
	pattern, err := m.AddPattern("admin", patternProposal("Runner-*.EXAMPLE"))
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
	exact, err := m.Enroll(proposal("runner-one.example"), "")
	require.NoError(t, err)
	h, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts)
	exact, err = m.Change("admin", "approve", exact.ID, exact.Revision, nil)
	require.NoError(t, err)
	h, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Policy.Accounts)
	_, err = m.Change("admin", "remove", exact.ID, exact.Revision, nil)
	require.NoError(t, err)
	h, before, err := m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts)

	updated := patternProposal("worker-**.example")
	_, err = m.Change("admin", "edit", pattern.ID, pattern.Revision, &updated)
	require.Error(t, err)
	updated.Pattern = "worker-*.example"
	pattern, err = m.Change("admin", "edit", pattern.ID, pattern.Revision, &updated)
	require.NoError(t, err)
	h, after, err := m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Nil(t, h)
	require.NotEqual(t, before, after)
	require.NoError(t, m.Close())
	restarted, err := OpenManaged(path)
	require.NoError(t, err)
	defer restarted.Close()
	record, err := restarted.Get(pattern.ID)
	require.NoError(t, err)
	require.Equal(t, pattern, record)
	h, _, err = restarted.LookupHost(t.Context(), "worker-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"worker-one.example"}, h.Policy.Names)
	_, err = restarted.Change("admin", "remove", pattern.ID, pattern.Revision, nil)
	require.NoError(t, err)
	h, _, err = restarted.LookupHost(t.Context(), "worker-one.example")
	require.NoError(t, err)
	require.Nil(t, h)
}

func TestManagedAmbiguousPatternsFailUntilDisambiguated(t *testing.T) {
	m, _ := managedFixture(t, "")
	first, err := m.AddPattern("admin", patternProposal("*.example"))
	require.NoError(t, err)
	second, err := m.Enroll(patternProposal("runner-*.*"), "")
	require.NoError(t, err)
	_, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err, "pending patterns are inert")
	second, err = m.Change("admin", "approve", second.ID, second.Revision, nil)
	require.NoError(t, err)
	_, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.ErrorIs(t, err, ErrConflict)
	// An exact record resolves the name even when patterns overlap.
	exact, err := m.Enroll(proposal("runner-one.example"), "")
	require.NoError(t, err)
	exact, err = m.Change("admin", "approve", exact.ID, exact.Revision, nil)
	require.NoError(t, err)
	h, _, err := m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Policy.Accounts)
	_, err = m.Change("admin", "remove", exact.ID, exact.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change("admin", "remove", first.ID, first.Revision, nil)
	require.NoError(t, err)
	_, _, err = m.LookupHost(t.Context(), "runner-one.example")
	require.NoError(t, err)
	_, err = m.AddPattern("admin", patternProposal(second.Proposal.Pattern))
	require.ErrorIs(t, err, ErrConflict)
}

func TestManagedPatternValidationAndCreationRollback(t *testing.T) {
	m, _ := managedFixture(t, "")
	for _, p := range []Proposal{
		proposal("exact"),
		{Names: []string{"exact"}, Pattern: "*", PrincipalMode: AccountNamePrincipals},
		patternProposal("bad-**.example"),
		{Pattern: "*.example", PrincipalMode: EpithetPrincipalV1, Realm: "epithet-host-id-v1:" + strings.Repeat("A", 43)},
	} {
		_, err := m.AddPattern("admin", p)
		require.Error(t, err)
	}
	_, before, err := m.LookupHost(t.Context(), "host.example")
	require.NoError(t, err)
	_, err = m.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'simulated failure'); END")
	require.NoError(t, err)
	_, err = m.AddPattern("admin", patternProposal("*.example"))
	require.ErrorIs(t, err, ErrStorage)
	records, err := m.List()
	require.NoError(t, err)
	require.Empty(t, records)
	events, err := m.Audit()
	require.NoError(t, err)
	require.Empty(t, events)
	_, after, err := m.LookupHost(t.Context(), "host.example")
	require.NoError(t, err)
	require.Equal(t, before, after)
}
