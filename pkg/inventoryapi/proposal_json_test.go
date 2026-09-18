package inventoryapi_test

import (
	"encoding/json"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/stretchr/testify/require"
)

func TestProposalJSONRequiresExplicitAccounts(t *testing.T) {
	for _, tc := range []struct {
		field   string
		want    []string
		invalid bool
	}{
		{"", nil, true},
		{`,"Accounts":null`, nil, true},
		{`,"accounts":null`, nil, false},
		{`,"accounts":[]`, []string{}, false},
		{`,"accounts":["deploy"]`, []string{"deploy"}, false},
		{`,"accounts":"deploy"`, nil, true},
		{`,"accounts":null,"status":"active"`, nil, true},
	} {
		t.Run(tc.field, func(t *testing.T) {
			data := []byte(`{"names":["host"],"labels":{},"principal-mode":"account-name"` + tc.field + `}`)
			var proposal inventoryapi.Proposal
			err := json.Unmarshal(data, &proposal)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, proposal.Accounts)
			require.Equal(t, "account-name", proposal.PrincipalMode)
			encoded, err := json.Marshal(proposal)
			require.NoError(t, err)
			require.JSONEq(t, string(data), string(encoded))
		})
	}
}
