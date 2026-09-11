package inventoryapi_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/stretchr/testify/require"
)

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
					HostResource: facts.HostResource{Names: tc.names, Accounts: json.RawMessage(`null`)},
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
