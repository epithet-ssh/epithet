package inventory_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The editor and on-disk documents must keep unrestricted (null) and empty
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
