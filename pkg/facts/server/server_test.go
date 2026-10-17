package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"github.com/stretchr/testify/require"
)

func TestServiceRoutesWithoutControlKey(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	store, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	directoryHandler, err := factserver.DirectoryHandler(&users{active: true}, public, "")
	require.NoError(t, err)
	inventoryHandler, err := factserver.InventoryHandler(store, public, "", factserver.WithInventoryManagement(store))
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
			directoryURL, inventoryURL := service.URL+"/lookup", ""
			if tc.name == "inventory" {
				directoryURL, inventoryURL = "", service.URL+"/lookup"
			}
			client, err := facts.NewDataClient(directoryURL, inventoryURL, key, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			if tc.name == "directory" {
				user, err := client.User(t.Context(), "id")
				require.NoError(t, err)
				require.Equal(t, "id", user.ID)
				require.True(t, user.Revision.IsZero())
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
	store, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	_, err = factserver.DirectoryHandler(&users{active: true}, public, public)
	require.ErrorContains(t, err, "distinct signing keys")
	_, err = factserver.InventoryHandler(store, public, public)
	require.ErrorContains(t, err, "distinct signing keys")
}

type inventoryContextKey struct{}

// Only the operations exercised by this fixture are implemented. Embedding the
// contract makes any unexpected operation fail instead of delegating to SQLite.
type alternateInventoryStore struct {
	inventory.Store
	record       inventory.Host
	event        inventory.AuditEvent
	contextValue any
	closed       bool
}

func (s *alternateInventoryStore) SupportsVersioning() bool { return false }

func (s *alternateInventoryStore) CreateHost(ctx context.Context, id string, p inventory.Host, event inventory.AuditEvent) (*inventory.Host, error) {
	s.event, s.contextValue = event, ctx.Value(inventoryContextKey{})
	s.record = p
	s.record.ID = id
	return &s.record, nil
}

func (s *alternateInventoryStore) LookupHost(ctx context.Context, name string) (*inventory.Host, error) {
	s.contextValue = ctx.Value(inventoryContextKey{})
	p := s.record
	return &inventory.Host{Names: []string{name}, Labels: p.Labels, Accounts: p.Accounts, PrincipalMode: p.PrincipalMode}, nil
}

func (s *alternateInventoryStore) Close() error {
	s.closed = true
	return nil
}

func TestInventoryServiceAcceptsAlternateManagedStore(t *testing.T) {
	caPublic, caKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	controlPublic, controlKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	store := &alternateInventoryStore{}
	handler, err := factserver.InventoryHandler(store, caPublic, controlPublic, factserver.WithInventoryManagement(store))
	require.NoError(t, err)
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), inventoryContextKey{}, "request-context")
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer service.Close()
	tls := tlsconfig.Config{Insecure: true}
	client, err := newSignedTestClient(service.URL, controlKey, serviceauth.InventoryAudience)
	require.NoError(t, err)
	p := facts.InventoryHost{Name: []string{"runner-*.example"}, Accounts: []string{"deploy"}, Attributes: map[string]string{"role": "runner"}, Principal: facts.InventoryPrincipal{Mode: string(inventory.AccountNamePrincipals)}}
	body, err := json.Marshal(facts.InventoryCreate{Host: &p})
	require.NoError(t, err)
	response, err := client.Do(t.Context(), "POST", "/inventory/records", nil, body, "admin")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, 201, response.StatusCode)
	var record facts.InventoryRecord
	require.NoError(t, json.NewDecoder(response.Body).Decode(&record))
	require.Equal(t, "admin", store.event.Actor)
	require.Equal(t, "add", store.event.Action)
	require.Equal(t, record.ID, store.event.Resource)
	require.Regexp(t, "^[0-9a-f]{64}$", record.ID)
	require.False(t, store.event.At.IsZero())
	require.Equal(t, "request-context", store.contextValue)
	require.Equal(t, p, *record.Host)

	data, err := facts.NewDataClient("", service.URL+"/lookup", caKey, tls)
	require.NoError(t, err)
	host, err := data.Host(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"runner-one.example"}, []string(host.Names))
	require.Equal(t, p.Accounts, host.Accounts)
	require.Equal(t, object.FromStrings(p.Attributes), host.Attributes)
	require.Equal(t, "request-context", store.contextValue)
	require.False(t, store.closed, "store lifetime belongs to the service caller")
}
