package server_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	directorysqlite "github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

// Expose only one plane's method set, even when the underlying test store
// implements both. The two views below use independently opened DB handles.
type directoryDataView struct{ directory.Directory }
type directoryManagementView struct{ directory.Store }
type inventoryDataView struct{ inventory.Hosts }
type inventoryManagementView struct{ inventory.Store }

func TestDirectoryManagementOption(t *testing.T) {
	caPublic, caKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	controlPublic, controlKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "directory.db")
	reader, err := directorysqlite.Open(path)
	require.NoError(t, err)
	defer reader.Close()
	writer, err := directorysqlite.Open(path)
	require.NoError(t, err)
	defer writer.Close()
	_, err = writer.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "existing"}, ExternalID: "existing", UserName: "existing", Active: true}, directory.NewAuditEvent(t.Context(), "create", "existing"))
	require.NoError(t, err)
	cfg := tlsconfig.Config{Insecure: true}
	// Supplying a source that implements Store must not implicitly enable SCIM.
	readonly, err := factserver.DirectoryHandler(reader, caPublic, controlPublic)
	require.NoError(t, err)
	readServer := httptest.NewServer(readonly)
	defer readServer.Close()
	data, err := facts.NewDataClient(readServer.URL+"/lookup", "", caKey, cfg)
	require.NoError(t, err)
	user, err := data.User(t.Context(), "existing")
	require.NoError(t, err)
	require.NotNil(t, user)
	provision, err := newSignedTestClient(readServer.URL, controlKey, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	response, err := provision.Do(t.Context(), "OPTIONS", "/lookup", nil, nil, "")
	require.NoError(t, err)
	response.Body.Close()
	_, advertised := wire.FindLinkTarget(response.Header, wire.RelSCIM)
	require.False(t, advertised)
	response, err = provision.Do(t.Context(), "GET", "/scim/v2/Users", nil, nil, "admin")
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 404, response.StatusCode)

	handler, err := factserver.DirectoryHandler(directoryDataView{reader}, caPublic, controlPublic, factserver.WithDirectoryManagement(directoryManagementView{writer}), factserver.WithSCIMUserIDAttribute("userName"))
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	defer server.Close()
	provision, err = newSignedTestClient(server.URL, controlKey, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	response, err = provision.Do(t.Context(), "OPTIONS", "/lookup", nil, nil, "")
	require.NoError(t, err)
	response.Body.Close()
	base, advertised := wire.FindLinkTarget(response.Header, wire.RelSCIM)
	require.True(t, advertised)
	require.Equal(t, "/scim/v2/", base)
	response, err = provision.Do(t.Context(), "POST", base+"Users", nil, []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"unrelated","userName":"new","active":true}`), "admin")
	require.NoError(t, err)
	created, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, 201, response.StatusCode, string(created))

	data, err = facts.NewDataClient(server.URL+"/lookup", "", caKey, cfg)
	require.NoError(t, err)
	user, err = data.User(t.Context(), "new")
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, "new", user.UserName)
	response, err = provision.Do(t.Context(), "GET", base+"Users", url.Values{"startIndex": {"1"}, "count": {"100"}}, nil, "admin")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, 200, response.StatusCode)
	var snapshot facts.SCIMPage
	require.NoError(t, json.NewDecoder(response.Body).Decode(&snapshot))
	require.Len(t, snapshot.Resources, 2)
	response, err = provision.Do(t.Context(), "GET", "/actor", url.Values{"id": {"new"}}, nil, "")
	require.NoError(t, err)
	defer response.Body.Close()
	var actor facts.ActorSnapshot
	require.NoError(t, json.NewDecoder(response.Body).Decode(&actor))
	require.Equal(t, "new", actor.User.ID)

}

func TestInventoryManagementOption(t *testing.T) {
	caPublic, caKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	controlPublic, controlKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "inventory.db")
	reader, err := inventorysqlite.Open(path)
	require.NoError(t, err)
	defer reader.Close()
	writer, err := inventorysqlite.Open(path)
	require.NoError(t, err)
	defer writer.Close()
	id1 := inventory.NewID()
	_, err = writer.AddHost(t.Context(), id1, inventory.Host{Names: []string{"old-*.example"}, Accounts: []string{"root"}, PrincipalMode: inventory.AccountNamePrincipals}, inventory.NewAuditEvent("admin", "add", id1))
	require.NoError(t, err)
	cfg := tlsconfig.Config{Insecure: true}
	readonly, err := factserver.InventoryHandler(reader, caPublic, controlPublic)
	require.NoError(t, err)
	readServer := httptest.NewServer(readonly)
	defer readServer.Close()
	data, err := facts.NewDataClient("", readServer.URL+"/lookup", caKey, cfg)
	require.NoError(t, err)
	host, err := data.Host(t.Context(), "old-host.example")
	require.NoError(t, err)
	require.NotNil(t, host)
	management, err := newSignedTestClient(readServer.URL, controlKey, serviceauth.InventoryAudience)
	require.NoError(t, err)
	response, err := management.Do(t.Context(), "POST", "/inventory/tokens", nil, []byte(`{"lifetimeSeconds":60}`), "admin")
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 404, response.StatusCode)

	handler, err := factserver.InventoryHandler(inventoryDataView{reader}, caPublic, controlPublic, factserver.WithInventoryManagement(inventoryManagementView{writer}))
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	defer server.Close()
	management, err = newSignedTestClient(server.URL, controlKey, serviceauth.InventoryAudience)
	require.NoError(t, err)
	response, err = management.Do(t.Context(), "POST", "/inventory/records", nil, []byte(`{"host":{"name":["new-*.example"],"attributes":null,"accounts":["deploy"],"principal":{"mode":"account-name"}}}`), "admin")
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 201, response.StatusCode)

	data, err = facts.NewDataClient("", server.URL+"/lookup", caKey, cfg)
	require.NoError(t, err)
	host, err = data.Host(t.Context(), "new-host.example")
	require.NoError(t, err)
	require.NotNil(t, host)
	require.Equal(t, []string{"deploy"}, host.Accounts)
}
