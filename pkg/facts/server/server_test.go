package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestServiceRoutesWithoutControlKey(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	store, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
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
	store, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	_, err = factserver.DirectoryHandler(&users{active: true}, nil, public, public)
	require.ErrorContains(t, err, "distinct signing keys")
	_, err = factserver.InventoryHandler(store, public, public)
	require.ErrorContains(t, err, "distinct signing keys")
}

type inventoryContextKey struct{}

// Only the operations exercised by this fixture are implemented. Embedding the
// contract makes any unexpected operation fail instead of delegating to SQLite.
type alternateInventoryStore struct {
	inventory.Store
	record       inventory.HostRecord
	actor        string
	contextValue any
	closed       bool
}

func (s *alternateInventoryStore) AddPattern(ctx context.Context, actor string, p inventory.Proposal) (*inventory.HostRecord, error) {
	s.actor, s.contextValue = actor, ctx.Value(inventoryContextKey{})
	s.record = inventory.HostRecord{ID: strings.Repeat("a", 64), Revision: 1, Status: "active", Proposal: p}
	return &s.record, nil
}

func (s *alternateInventoryStore) LookupHost(ctx context.Context, name string) (*inventory.ResolvedHost, string, error) {
	s.contextValue = ctx.Value(inventoryContextKey{})
	p := s.record.Proposal
	return &inventory.ResolvedHost{Policy: inventory.Host{Names: []string{name}, Labels: p.Labels, Accounts: p.Accounts}, PrincipalMode: p.PrincipalMode}, "opaque-backend-revision", nil
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
	handler, err := factserver.InventoryHandler(store, caPublic, controlPublic)
	require.NoError(t, err)
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), inventoryContextKey{}, "request-context")
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer service.Close()
	tls := tlsconfig.Config{Insecure: true}
	control, err := facts.NewControlClient("", service.URL, controlKey, tls)
	require.NoError(t, err)
	p := facts.Proposal{Pattern: "runner-*.example", Accounts: []string{"deploy"}, Labels: map[string]string{"role": "runner"}, PrincipalMode: string(inventory.AccountNamePrincipals)}
	record, err := control.AddPattern(t.Context(), facts.Authorization{Actor: "admin"}, p)
	require.NoError(t, err)
	require.Equal(t, "admin", store.actor)
	require.Equal(t, "request-context", store.contextValue)
	require.Equal(t, p, record.Proposal)

	data, err := facts.NewDataClient("", service.URL, caKey, tls)
	require.NoError(t, err)
	host, err := data.Host(t.Context(), "runner-one.example")
	require.NoError(t, err)
	require.Equal(t, []string{"runner-one.example"}, host.Names)
	require.Equal(t, p.Accounts, host.Accounts)
	require.Equal(t, p.Labels, host.Labels)
	require.Equal(t, "opaque-backend-revision", host.Revision.String())
	require.Equal(t, "request-context", store.contextValue)
	require.False(t, store.closed, "store lifetime belongs to the service caller")
}
