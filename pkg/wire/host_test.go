package wire_test

import (
	"encoding/json"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestHostDecodingPreservesPrincipalAndAccountRestrictions(t *testing.T) {
	for _, tc := range []struct {
		field   string
		want    []string
		invalid bool
	}{
		{"", nil, true},
		{`,"accounts":null`, nil, false},
		{`,"accounts":[]`, []string{}, false},
		{`,"accounts":["deploy"]`, []string{"deploy"}, false},
		{`,"accounts":"deploy"`, nil, true},
	} {
		t.Run(tc.field, func(t *testing.T) {
			data := []byte(`{"names":["host.example.com"],"labels":{"env":"prod"},"principal":{"mode":"epithet-principal-v1","domain":"production"}` + tc.field + `}`)
			var host wire.Host
			err := json.Unmarshal(data, &host)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, host.Accounts)
			require.Equal(t, []string{"host.example.com"}, host.Names)
			require.Equal(t, map[string]string{"env": "prod"}, host.Labels)
			require.Equal(t, wire.Principal{Mode: "epithet-principal-v1", Domain: "production"}, host.Principal)
			encoded, err := json.Marshal(host)
			require.NoError(t, err)
			require.JSONEq(t, string(data), string(encoded))
		})
	}
}

func TestPrincipalBindingWithMultipleNames(t *testing.T) {
	const generated = "epithet-host-id-v1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	for _, tc := range []struct {
		name, mode, domain string
		names              []string
		valid              bool
	}{
		{"account name", "account-name", "", []string{"first", "second"}, true},
		{"generated domain", "epithet-principal-v1", generated, []string{"first", "second"}, true},
		{"missing target", "epithet-principal-v1", generated, []string{"first"}, false},
		{"domain cannot replace target", "epithet-principal-v1", "production", []string{"production"}, false},
		{"host alias may coincide with domain", "epithet-principal-v1", "production", []string{"production", "second"}, true},
		{"named domain", "epithet-principal-v1", "production", []string{"second"}, true},
		{"named domain multiple names", "epithet-principal-v1", "production", []string{"first", "second"}, true},
		{"account name missing target", "account-name", "", []string{"first"}, false},
		{"missing domain", "epithet-principal-v1", "", []string{"second"}, false},
		{"invalid domain", "epithet-principal-v1", "not a domain", []string{"second"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := wire.Host{HostResource: wire.HostResource{Names: tc.names, Accounts: nil}, Principal: wire.Principal{Mode: tc.mode, Domain: tc.domain}}

			if tc.valid {
				require.NoError(t, r.Validate("second"))
			} else {
				require.Error(t, r.Validate("second"))
			}
		})
	}
}
