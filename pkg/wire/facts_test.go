package wire_test

import (
	"encoding/json"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestHostAccountsDecodeAtBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        []string
		invalid     bool
	}{
		{"omitted", "", nil, true},
		{"null", `,"accounts":null`, nil, false},
		{"empty", `,"accounts":[]`, []string{}, false},
		{"list", `,"accounts":["deploy"]`, []string{"deploy"}, false},
		{"string", `,"accounts":"deploy"`, nil, true},
		{"object", `,"accounts":{}`, nil, true},
		{"invalid member", `,"accounts":[1]`, nil, true},
		{"unknown field", `,"accounts":null,"principal":{}`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"names":["host"],"labels":{"env":"prod"}` + tc.field + `}`)
			// Reusing a destination must not retain restrictions from its last
			// value, and malformed input must not replace that value.
			host := wire.HostResource{Names: []string{"old"}, Accounts: []string{"old"}}
			err := json.Unmarshal(data, &host)
			if tc.invalid {
				require.Error(t, err)
				require.Equal(t, []string{"old"}, host.Accounts)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, host.Accounts)
			require.Equal(t, []string{"host"}, host.Names)
			require.Equal(t, map[string]string{"env": "prod"}, host.Labels)
			encoded, err := json.Marshal(host)
			require.NoError(t, err)
			require.JSONEq(t, string(data), string(encoded))
		})
	}
}
