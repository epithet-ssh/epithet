package inventoryapi_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
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
			data := []byte(`{"names":["production"],"labels":{"env":"prod"},"principal":{"mode":"epithet-principal-v1","domain":"production"}` + tc.field + `}`)
			var host inventoryapi.Host
			err := json.Unmarshal(data, &host)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, host.Accounts)
			require.Equal(t, []string{"production"}, host.Names)
			require.Equal(t, map[string]string{"env": "prod"}, host.Labels)
			require.Equal(t, inventoryapi.Principal{Mode: "epithet-principal-v1", Domain: "production"}, host.Principal)
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
		{"shared domain", "epithet-principal-v1", "production", []string{"production"}, true},
		{"member name in domain projection", "epithet-principal-v1", "production", []string{"production", "second"}, false},
		{"member instead of domain", "epithet-principal-v1", "production", []string{"second"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := inventoryapi.Resolution{
				Version: inventoryapi.Version, Target: "second",
				Authentication: facts.Authentication{ID: "id", ExpiresAt: time.Now().Add(time.Hour)},
				Directory:      inventoryapi.DirectorySnapshot{Revision: "directory"},
				Inventory: inventoryapi.HostSnapshot{Revision: "inventory", Host: &inventoryapi.Host{
					HostResource: facts.HostResource{Names: tc.names, Accounts: nil},
					Principal:    inventoryapi.Principal{Mode: tc.mode, Domain: tc.domain},
				}},
			}
			if tc.valid {
				require.NoError(t, r.Validate("second"))
			} else {
				require.Error(t, r.Validate("second"))
			}
		})
	}
}
