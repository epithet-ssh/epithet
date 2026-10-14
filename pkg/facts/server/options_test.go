package server_test

import (
	"io"
	"net/http/httptest"
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
	_, err = writer.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "existing", UserName: "existing", Active: true})
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

	handler, err := factserver.DirectoryHandler(directoryDataView{reader}, caPublic, controlPublic, factserver.WithDirectoryManagement(directoryManagementView{writer}))
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
	response, err = provision.Do(t.Context(), "POST", base+"Users", nil, []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"new","userName":"new","active":true}`), "admin")
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
	control, err := facts.NewControlClient(server.URL, "", controlKey, cfg)
	require.NoError(t, err)
	// The data view lacks UserLister: administrative listing belongs to management.
	snapshot, err := control.Users(t.Context(), facts.Authorization{Actor: "admin"})
	require.NoError(t, err)
	require.Len(t, snapshot.Users, 2)
	actor, _, err := control.Actor(t.Context(), "new")
	require.NoError(t, err)
	require.Equal(t, "new", actor.ID)
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
	_, err = writer.AddPattern(t.Context(), "admin", inventory.Proposal{Pattern: "old-*.example", Accounts: []string{"root"}, PrincipalMode: inventory.AccountNamePrincipals})
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
	control, err := facts.NewControlClient("", readServer.URL+"/lookup", controlKey, cfg)
	require.NoError(t, err)
	_, err = control.CreateToken(t.Context(), facts.Authorization{Actor: "admin"}, 60)
	require.ErrorIs(t, err, facts.ErrNotFound)

	handler, err := factserver.InventoryHandler(inventoryDataView{reader}, caPublic, controlPublic, factserver.WithInventoryManagement(inventoryManagementView{writer}))
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	defer server.Close()
	control, err = facts.NewControlClient("", server.URL+"/lookup", controlKey, cfg)
	require.NoError(t, err)
	_, err = control.AddPattern(t.Context(), facts.Authorization{Actor: "admin"}, facts.Proposal{Pattern: "new-*.example", Accounts: []string{"deploy"}, PrincipalMode: "account-name"})
	require.NoError(t, err)
	data, err = facts.NewDataClient("", server.URL+"/lookup", caKey, cfg)
	require.NoError(t, err)
	host, err = data.Host(t.Context(), "new-host.example")
	require.NoError(t, err)
	require.NotNil(t, host)
	require.Equal(t, []string{"deploy"}, host.Accounts)
}
