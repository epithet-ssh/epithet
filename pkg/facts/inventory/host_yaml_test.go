package inventory_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The editor must keep unrestricted (null) and empty
// ([]) account sets distinct through a marshal and parse cycle.
func TestHostYAMLRoundTripPreservesAccounts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		accounts []string
	}{
		{"null", nil},
		{"empty", []string{}},
		{"list", []string{"deploy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := inventory.Host{Names: []string{"host"}, Labels: map[string]string{}, Accounts: tc.accounts, PrincipalMode: inventory.AccountNamePrincipals}
			data, err := yaml.Marshal(p)
			require.NoError(t, err)
			parsed, err := inventory.ParseHost(data)
			require.NoError(t, err)
			require.Equal(t, tc.accounts, parsed.Accounts)
			require.Equal(t, p, parsed)
		})
	}
}

func TestHostEditorDraftShowsRealm(t *testing.T) {
	data, err := yaml.Marshal(inventory.Host{Names: []string{"ci-*.example"}, Accounts: []string{}, PrincipalMode: inventory.EpithetPrincipalV1})
	require.NoError(t, err)
	require.Contains(t, string(data), "realm: \"\"")
}

func TestHostNamesIncludeWildcards(t *testing.T) {
	host, err := inventory.ParseHost([]byte("names: [Host.EXAMPLE, '*.EXAMPLE', 'ci-?.example']\nlabels: {}\naccounts: []\nprincipal-mode: account-name\n"))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"host.example", "*.example", "ci-?.example"}, host.Names)
	data, err := yaml.Marshal(host)
	require.NoError(t, err)
	roundTrip, err := inventory.ParseHost(data)
	require.NoError(t, err)
	require.Equal(t, host, roundTrip)
}
