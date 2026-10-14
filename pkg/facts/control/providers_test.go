package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestAuditCursorsAreForwardedUnchanged(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	const cursor = "backend/page:+/= token"
	const next = "another backend token:雪"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "OPTIONS":
			w.Header().Add("Link-Template", `"/records{/id}"; rel="`+facts.InventoryRecordsRelation+`"`)
			w.Header().Add("Link-Template", `"/tokens{?token}"; rel="`+facts.InventoryTokensRelation+`"`)
			w.Header().Add("Link-Template", `"/audit{?cursor,limit}"; rel="`+facts.InventoryAuditRelation+`"`)
			w.WriteHeader(204)
		case r.URL.Path == "/audit":
			require.Equal(t, cursor, r.URL.Query().Get("cursor"))
			require.Equal(t, "7", r.URL.Query().Get("limit"))
			require.NoError(t, json.NewEncoder(w).Encode(facts.AuditPage[facts.HostAuditEvent]{Events: []facts.HostAuditEvent{}, Next: next}))
		case r.URL.Path == "/manage":
			var envelope facts.ControlEnvelope
			require.NoError(t, json.NewDecoder(r.Body).Decode(&envelope))
			require.Equal(t, cursor, envelope.Request.AuditCursor)
			require.Equal(t, 7, envelope.Request.AuditLimit)
			require.NoError(t, json.NewEncoder(w).Encode(facts.ControlResponse{DirectoryAudit: &facts.AuditPage[facts.DirectoryAuditEvent]{Events: []facts.DirectoryAuditEvent{}, Next: next}}))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
	}))
	defer server.Close()
	client, err := newProviderTestServer(server.URL, server.URL, key, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	auth := authorization{Actor: "admin"}
	hosts, err := client.hostAudit(t.Context(), auth, cursor, 7)
	require.NoError(t, err)
	require.Equal(t, next, hosts.Next)
	users, err := client.directoryAudit(t.Context(), auth, cursor, 7)
	require.NoError(t, err)
	require.Equal(t, next, users.Next)
}

func TestClientPlanesRouteAndPreserveAuthorization(t *testing.T) {
	readerPublic, readerKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	controlPublic, controlKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	users, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer users.Close()
	_, err = users.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "admin"}, ExternalID: "admin", UserName: "admin", Active: true}, directory.NewAuditEvent(t.Context(), "create", "admin"))
	require.NoError(t, err)
	_, err = users.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "disabled"}, ExternalID: "disabled", UserName: "disabled", Active: false}, directory.NewAuditEvent(t.Context(), "create", "disabled"))
	require.NoError(t, err)
	_, err = users.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-ops"}, DisplayName: "ops"}, directory.NewAuditEvent(t.Context(), "create", "group-ops"))
	require.NoError(t, err)
	// Same-name groups remain distinct resources.
	_, err = users.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "other-ops"}, DisplayName: "ops"}, directory.NewAuditEvent(t.Context(), "create", "other-ops"))
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
	dir := serve(factserver.DirectoryHandler(users, readerPublic, controlPublic, factserver.WithDirectoryManagement(users)))
	inv := serve(factserver.InventoryHandler(hosts, readerPublic, controlPublic, factserver.WithInventoryManagement(hosts)))
	cfg := tlsconfig.Config{Insecure: true}
	data, err := facts.NewDataClient(dir.URL+"/lookup", inv.URL+"/lookup", readerKey, cfg)
	require.NoError(t, err)
	control, err := newProviderTestServer(dir.URL, inv.URL+"/lookup", controlKey, cfg)
	require.NoError(t, err)
	user, err := data.User(t.Context(), "admin")
	require.NoError(t, err)
	require.Equal(t, "admin", user.ID)
	inactive, err := data.User(t.Context(), "disabled")
	require.NoError(t, err)
	require.Nil(t, inactive)
	actor, err := control.directoryActor(t.Context(), "disabled")
	require.NoError(t, err)
	require.False(t, actor.Active)
	auth := authorization{Actor: "admin"}
	caps, err := control.providerCapabilities(t.Context())
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"admin", "enroll", "directory"}, caps.Capabilities)
	directoryEvents, err := control.directoryAudit(t.Context(), auth, "", 0)
	require.NoError(t, err)
	require.NotEmpty(t, directoryEvents.Events)
	proposal := facts.InventoryInput{Names: []string{"host"}, Accounts: []string{"root"}, PrincipalMode: "account-name"}
	host, err := control.enroll(t.Context(), proposal, "")
	require.NoError(t, err)
	require.Equal(t, "pending", host.Status)
	resolved, err := data.Host(t.Context(), "host")
	require.NoError(t, err)
	require.Nil(t, resolved)
	_, err = control.approveHost(t.Context(), auth, host.ID, host.Revision+1)
	var rejected *facts.ServiceError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, http.StatusPreconditionFailed, rejected.Status)
	host, err = control.approveHost(t.Context(), auth, host.ID, host.Revision)
	require.NoError(t, err)
	resolved, err = data.Host(t.Context(), "host")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, resolved.Accounts)
	proposal.Accounts = []string{}
	host, err = control.editHost(t.Context(), auth, host.ID, host.Revision, proposal)
	require.NoError(t, err)
	got, err := control.host(t.Context(), auth, host.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Host.Accounts)
	require.Empty(t, got.Host.Accounts)
	records, err := control.hosts(t.Context(), auth, "", 0, false)
	require.NoError(t, err)
	require.Len(t, records, 1)
	pattern, err := control.addHost(t.Context(), auth, facts.InventoryInput{Names: []string{"ci-*"}, Accounts: []string{"root"}, PrincipalMode: "account-name"})
	require.NoError(t, err)
	require.Equal(t, "active", pattern.Status)
	token, err := control.createToken(t.Context(), auth, 60)
	require.NoError(t, err)
	require.NoError(t, control.revokeToken(t.Context(), auth, token.ID))
	events, err := control.hostAudit(t.Context(), auth, "", 0)
	require.NoError(t, err)
	require.NotEmpty(t, events.Events)
	for _, event := range events.Events {
		if event.Action != "enroll" {
			require.Equal(t, "admin", event.Actor)
		}
	}
	require.NoError(t, control.removeHost(t.Context(), auth, host.ID, host.Revision))
	_, err = control.host(t.Context(), auth, host.ID)
	require.ErrorIs(t, err, facts.ErrNotFound)
	proposal.Names = []string{"denied"}
	pending, err := control.enroll(t.Context(), proposal, "")
	require.NoError(t, err)
	denied, err := control.denyHost(t.Context(), auth, pending.ID, pending.Revision)
	require.NoError(t, err)
	require.Equal(t, "denied", denied.Status)
	wrong, err := newProviderTestServer(dir.URL, inv.URL+"/lookup", readerKey, cfg)
	require.NoError(t, err)
	_, err = wrong.createToken(t.Context(), auth, 60)
	require.ErrorIs(t, err, facts.ErrNotFound)
}

func TestControlActorIdentityMismatch(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(public, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		actor, err := verifier.VerifyActor(r, body)
		require.NoError(t, err)
		require.Empty(t, actor)
		require.Equal(t, "/actor", r.URL.Path)
		fmt.Fprint(w, `{"user":{"ID":"other"}}`)
	}))
	defer server.Close()
	client, err := newProviderTestServer(server.URL, server.URL, key, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	// Actor identity mismatch cannot become an authorization success.
	_, err = client.directoryActor(t.Context(), "admin")
	require.ErrorContains(t, err, "actor identity mismatch")
}

func TestProviderOperationsRejectMalformedAndOversizedResults(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	for _, body := range []string{`{}`, `{"host":`, strings.Repeat("x", (8<<20)+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "OPTIONS" {
				w.Header().Add("Link-Template", `"/records{/id}"; rel="`+facts.InventoryRecordsRelation+`"`)
				w.Header().Add("Link-Template", `"/tokens{?token}"; rel="`+facts.InventoryTokensRelation+`"`)
				w.Header().Add("Link-Template", `"/audit{?cursor,limit}"; rel="`+facts.InventoryAuditRelation+`"`)
				w.WriteHeader(204)
				return
			}
			fmt.Fprint(w, body)
		}))
		client, err := newProviderTestServer("", server.URL, key, tlsconfig.Config{Insecure: true})
		require.NoError(t, err)
		_, err = client.host(t.Context(), authorization{Actor: "admin"}, "id")
		require.ErrorIs(t, err, facts.ErrUnavailable)
		server.Close()
	}
}

// Construct only provider dependencies for protocol tests; public authorization
// is exercised separately through the control HTTP handler.
func newProviderTestServer(directoryURL, inventoryURL string, key sshcert.RawPrivateKey, cfg tlsconfig.Config) (*Server, error) {
	s := &Server{}
	var err error
	if directoryURL != "" {
		s.directoryBackend, err = servicehttp.New(directoryURL, "", key, serviceauth.DirectoryAudience, cfg)
		if err != nil {
			return nil, err
		}
	}
	if inventoryURL != "" {
		s.inventory, err = servicehttp.New(inventoryURL, "/lookup", key, serviceauth.InventoryAudience, cfg)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}
