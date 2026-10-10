package facts_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestClientPlanesRouteAndPreserveAuthorization(t *testing.T) {
	readerPublic, readerKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	controlPublic, controlKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	users, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer users.Close()
	_, err = users.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "admin", UserName: "admin", Active: true})
	require.NoError(t, err)
	_, err = users.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "disabled", UserName: "disabled", Active: false})
	require.NoError(t, err)
	_, err = users.CreateGroup(t.Context(), directory.Group{DisplayName: "ops"})
	require.NoError(t, err)
	// A second group with the same display name awaits an explicit rebind.
	group, err := users.CreateGroup(t.Context(), directory.Group{DisplayName: "ops"})
	require.NoError(t, err)
	hosts, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer hosts.Close()
	serve := func(handler http.Handler, err error) *httptest.Server {
		require.NoError(t, err)
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		return server
	}
	dir := serve(factserver.DirectoryHandler(users, users, readerPublic, controlPublic))
	inv := serve(factserver.InventoryHandler(hosts, readerPublic, controlPublic))
	cfg := tlsconfig.Config{Insecure: true}
	data, err := facts.NewDataClient(dir.URL, inv.URL, readerKey, cfg)
	require.NoError(t, err)
	control, err := facts.NewControlClient(dir.URL, inv.URL, controlKey, cfg)
	require.NoError(t, err)
	user, err := data.User(t.Context(), "admin")
	require.NoError(t, err)
	require.Equal(t, "admin", user.ID)
	inactive, err := data.User(t.Context(), "disabled")
	require.NoError(t, err)
	require.Nil(t, inactive)
	actor, _, err := control.Actor(t.Context(), "disabled")
	require.NoError(t, err)
	require.False(t, actor.Active)
	_, revision, err := control.Actor(t.Context(), "admin")
	require.NoError(t, err)
	auth := facts.Authorization{Actor: "admin", DirectoryRevision: revision}
	caps, err := control.Capabilities(t.Context())
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"admin", "enroll", "directory", "directory-users"}, caps.Capabilities)
	snapshot, err := control.Bindings(t.Context(), auth)
	require.NoError(t, err)
	require.NoError(t, control.BindGroup(t.Context(), auth, "ops", group.ID, snapshot.Revision))
	// The binding changed authorization. Reusing the old actor snapshot must
	// still fail even if the caller has refreshed the binding's own revision.
	snapshot, err = control.Bindings(t.Context(), auth)
	require.NoError(t, err)
	require.ErrorIs(t, control.BindGroup(t.Context(), auth, "ops", group.ID, snapshot.Revision), facts.ErrConflict)
	_, revision, err = control.Actor(t.Context(), "admin")
	require.NoError(t, err)
	auth.DirectoryRevision = revision
	directoryEvents, err := control.DirectoryAudit(t.Context(), auth, 0, 0)
	require.NoError(t, err)
	require.NotEmpty(t, directoryEvents)
	userSnapshot, err := control.Users(t.Context(), auth)
	require.NoError(t, err)
	require.Len(t, userSnapshot.Users, 2)
	proposal := facts.Proposal{Names: []string{"host"}, Accounts: []string{"root"}, PrincipalMode: "account-name"}
	host, err := control.Enroll(t.Context(), proposal, "")
	require.NoError(t, err)
	require.Equal(t, "pending", host.Status)
	resolved, err := data.Host(t.Context(), "host")
	require.NoError(t, err)
	require.Nil(t, resolved)
	_, err = control.ApproveHost(t.Context(), auth, host.ID, host.Revision+1)
	require.ErrorIs(t, err, facts.ErrConflict)
	host, err = control.ApproveHost(t.Context(), auth, host.ID, host.Revision)
	require.NoError(t, err)
	resolved, err = data.Host(t.Context(), "host")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, resolved.Accounts)
	proposal.Accounts = []string{}
	host, err = control.EditHost(t.Context(), auth, host.ID, host.Revision, proposal)
	require.NoError(t, err)
	got, err := control.Host(t.Context(), auth, host.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Proposal.Accounts)
	require.Empty(t, got.Proposal.Accounts)
	records, err := control.Hosts(t.Context(), auth, "", 0, false)
	require.NoError(t, err)
	require.Len(t, records, 1)
	pattern, err := control.AddPattern(t.Context(), auth, facts.Proposal{Pattern: "ci-*", Accounts: []string{"root"}, PrincipalMode: "account-name"})
	require.NoError(t, err)
	require.Equal(t, "active", pattern.Status)
	token, err := control.CreateToken(t.Context(), auth, 60)
	require.NoError(t, err)
	tokens, err := control.Tokens(t.Context(), auth, "", 0)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	require.NoError(t, control.RevokeToken(t.Context(), auth, token.ID))
	events, err := control.HostAudit(t.Context(), auth, 0, 0)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	for _, event := range events {
		if event.Action != "enroll" {
			require.Equal(t, "admin", event.Actor)
		}
	}
	require.NoError(t, control.RemoveHost(t.Context(), auth, host.ID, host.Revision))
	_, err = control.Host(t.Context(), auth, host.ID)
	require.ErrorIs(t, err, facts.ErrNotFound)
	proposal.Names = []string{"denied"}
	pending, err := control.Enroll(t.Context(), proposal, "")
	require.NoError(t, err)
	denied, err := control.DenyHost(t.Context(), auth, pending.ID, pending.Revision)
	require.NoError(t, err)
	require.Equal(t, "denied", denied.Status)
	wrong, err := facts.NewControlClient(dir.URL, inv.URL, readerKey, cfg)
	require.NoError(t, err)
	_, err = wrong.CreateToken(t.Context(), auth, 60)
	require.ErrorIs(t, err, facts.ErrDenied)
}

func TestTypedControlResponsesAndProvisioningMetadata(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := facts.NewVerifierFor(public, facts.DirectoryAudience)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		actor, err := verifier.VerifyActor(r, body)
		require.NoError(t, err)
		require.Empty(t, actor)
		switch r.URL.Path {
		case "/manage":
			// This is valid JSON but not a host-administration result.
			fmt.Fprint(w, `{}`)
		case "/actor":
			fmt.Fprint(w, `{"user":{"ID":"other"}}`)
		case "/scim":
			var req facts.SCIMRequest
			require.NoError(t, json.Unmarshal(body, &req))
			require.Equal(t, "DELETE", req.Method)
			require.Equal(t, "/scim/v2/Users/id?attributes=id", req.Target)
			require.Equal(t, `W/"3"`, req.IfMatch)
			require.Equal(t, "application/scim+json", req.ContentType)
			w.Header().Set("Content-Type", "application/scim+json")
			w.Header().Set("ETag", `W/"4"`)
			w.Header().Set("Location", "/scim/v2/Users/id")
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			w.Header().Set("Authorization", "must-not-escape")
			w.WriteHeader(412)
			fmt.Fprint(w, `{"status":"412","detail":"stale revision"}`)
		}
	}))
	defer server.Close()
	client, err := facts.NewControlClient(server.URL, server.URL, key, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	// Actor identity mismatch cannot become an authorization success.
	_, _, err = client.Actor(t.Context(), "admin")
	require.ErrorContains(t, err, "actor identity mismatch")
	result, err := client.Provision(t.Context(), facts.SCIMRequest{Method: "DELETE", Target: "/scim/v2/Users/id?attributes=id", ContentType: "application/scim+json", IfMatch: `W/"3"`})
	require.NoError(t, err)
	require.Equal(t, 412, result.Status)
	require.Equal(t, `W/"4"`, result.ETag)
	require.Equal(t, "/scim/v2/Users/id", result.Location)
	require.Equal(t, "application/scim+json", result.ContentType)
	require.Equal(t, `Bearer realm="scim"`, result.WWWAuthenticate)
	require.JSONEq(t, `{"status":"412","detail":"stale revision"}`, string(result.Body))
}

func TestControlClientRejectsMalformedAndOversizedResults(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	for _, body := range []string{`{}`, `{"host":`, strings.Repeat("x", (8<<20)+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		client, err := facts.NewControlClient("", server.URL, key, tlsconfig.Config{Insecure: true})
		require.NoError(t, err)
		_, err = client.Host(t.Context(), facts.Authorization{Actor: "admin"}, "id")
		require.ErrorIs(t, err, facts.ErrUnavailable)
		server.Close()
	}
}
