package server_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestServiceRoutesWithoutControlKey(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	store, err := inventory.OpenManaged(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	directoryHandler, err := factserver.DirectoryHandler(&users{active: true}, nil, public, "")
	require.NoError(t, err)
	inventoryHandler, err := factserver.InventoryHandler(store, public, "")
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		handler http.Handler
	}{
		{"directory", directoryHandler},
		{"inventory", inventoryHandler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := httptest.NewServer(tc.handler)
			defer service.Close()
			directoryURL, inventoryURL := service.URL, ""
			if tc.name == "inventory" {
				directoryURL, inventoryURL = "", service.URL
			}
			client, err := facts.NewDataClient(directoryURL, inventoryURL, key, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			if tc.name == "directory" {
				user, err := client.User(t.Context(), "id")
				require.NoError(t, err)
				require.Equal(t, "id", user.ID)
				require.Equal(t, "opaque-revision", user.Revision.String())
			} else {
				host, err := client.Host(t.Context(), "missing")
				require.NoError(t, err)
				require.Nil(t, host)
			}
			for _, path := range []string{"/manage", "/actor", "/scim"} {
				response, err := http.Get(service.URL + path)
				require.NoError(t, err)
				response.Body.Close()
				require.Equal(t, http.StatusNotFound, response.StatusCode, path)
			}
		})
	}
}

func TestServiceConstructorsEnforceDistinctReaderAndControlKeys(t *testing.T) {
	public, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	store, err := inventory.OpenManaged(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	_, err = factserver.DirectoryHandler(&users{active: true}, nil, public, public)
	require.ErrorContains(t, err, "distinct signing keys")
	_, err = factserver.InventoryHandler(store, public, public)
	require.ErrorContains(t, err, "distinct signing keys")
}
