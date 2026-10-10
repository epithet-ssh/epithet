package inventory_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The editor must keep unrestricted (null) and empty
// ([]) account sets distinct through a marshal and parse cycle.
func TestProposalYAMLRoundTripPreservesAccounts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		accounts []string
	}{
		{"null", nil},
		{"empty", []string{}},
		{"list", []string{"deploy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := inventory.Proposal{Names: []string{"host"}, Labels: map[string]string{}, Accounts: tc.accounts, PrincipalMode: inventory.AccountNamePrincipals}
			data, err := yaml.Marshal(p)
			require.NoError(t, err)
			parsed, err := inventory.ParseProposal(data)
			require.NoError(t, err)
			require.Equal(t, tc.accounts, parsed.Accounts)
			require.Equal(t, p.ControlProposal(), parsed.ControlProposal())
		})
	}
}

func TestPatternEditorDraftShowsRealm(t *testing.T) {
	data, err := yaml.Marshal(inventory.Proposal{Pattern: "ci-*.example", Accounts: []string{}, PrincipalMode: inventory.EpithetPrincipalV1})
	require.NoError(t, err)
	require.Contains(t, string(data), "realm: \"\"")
}
