package control_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/control"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/test/controltest"
	"github.com/stretchr/testify/require"
)

func TestSeparateRolesAndBackendAuthority(t *testing.T) {
	users, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer users.Close()
	for _, id := range []string{"directory-admin", "inventory-admin"} {
		_, err = users.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "subject:" + id, UserName: id, Active: true})
		require.NoError(t, err)
	}
	hosts, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer hosts.Close()
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(t.Context(), oidc.Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	f := controltest.New(t, users, users, hosts, control.Config{Validator: validator, DirectoryAdmins: control.Admins{Users: []string{"subject:directory-admin"}}, InventoryAdmins: control.Admins{Users: []string{"subject:inventory-admin"}}, SCIMToken: "provisioning-secret"})
	client, err := facts.NewAdminClient(f.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for _, id := range []string{"directory-admin", "inventory-admin"} {
		token := idp.MintIDToken(id, time.Now().Add(time.Hour))
		for _, action := range []string{"directory-users", "list"} {
			_, status, err := client.Control(t.Context(), token, facts.ControlRequest{Action: action})
			if (id == "directory-admin") == (action == "directory-users") {
				require.NoError(t, err)
				require.Equal(t, 200, status)
			} else {
				require.Error(t, err)
				require.Equal(t, 403, status)
			}
		}
	}
	// The public request cannot supply audit identity or a private envelope.
	for _, body := range []string{`{"action":"token-create","actor":"subject:inventory-admin"}`, `{"request":{"action":"token-create"},"authorizationRevision":"forged"}`} {
		req := httptest.NewRequest("POST", "/manage", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+idp.MintIDToken("inventory-admin", time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		f.Control.ServeHTTP(rec, req)
		require.Equal(t, 400, rec.Code)
	}
	for _, key := range []sshcert.RawPrivateKey{f.CAKey, f.ControlKey} {
		private, err := facts.NewControlClient("", f.InventoryURL, key, tlsconfig.Config{Insecure: true})
		require.NoError(t, err)
		_, err = private.CreateToken(t.Context(), facts.Authorization{Actor: "subject:inventory-admin"}, 0)
		if key == f.CAKey {
			require.ErrorIs(t, err, facts.ErrDenied)
			var rejected *facts.ServiceError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, 403, rejected.Status)
		} else {
			require.NoError(t, err)
		}

	}
	events, err := hosts.Audit(t.Context())
	require.NoError(t, err)
	require.Equal(t, "subject:inventory-admin", events[len(events)-1].Actor)
	// The provisioning bearer belongs to public control only, never the backend.
	for _, endpoint := range []string{f.URL + "/scim/v2/Users", f.DirectoryURL + "/scim"} {
		req, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer provisioning-secret")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		if endpoint == f.URL+"/scim/v2/Users" {
			require.Equal(t, 200, resp.StatusCode)
		} else {
			require.Equal(t, 403, resp.StatusCode)
		}
	}
	// SCIM mutation still records the backend-owned nonhuman actor.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"new-id","userName":"new-user","active":true}`
	req, err := http.NewRequest("POST", f.URL+"/scim/v2/Users", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer provisioning-secret")
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 201, resp.StatusCode)
	var created map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	audit, err := users.Audit(t.Context(), 0, 0)
	require.NoError(t, err)
	require.Equal(t, "scim", audit[len(audit)-1].Actor)
	// If-Match must survive the signed hop, so a stale write fails.
	req, err = http.NewRequest("DELETE", f.URL+"/scim/v2/Users/"+created["id"].(string), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer provisioning-secret")
	req.Header.Set("If-Match", `W/"0"`)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 412, resp.StatusCode)
}

func TestCustomDirectoryNeedsOnlyLookup(t *testing.T) {
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(t.Context(), oidc.Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	hosts, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer hosts.Close()
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := facts.NewVerifierFor(pub, facts.DirectoryAudience)
	require.NoError(t, err)
	custom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, verifier.Verify(r, nil))
		require.Equal(t, "/lookup", r.URL.Path)
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "subject:admin", r.URL.Query().Get("id"))
		json.NewEncoder(w).Encode(facts.User{ID: "subject:admin"})
	}))
	defer custom.Close()
	handler, err := factserver.InventoryHandler(hosts, "", pub)
	require.NoError(t, err)
	backend := httptest.NewServer(handler)
	defer backend.Close()
	control, err := control.New(control.Config{Key: key, DirectoryURL: custom.URL, InventoryBackendURL: backend.URL, Validator: validator, InventoryAdmins: control.Admins{Users: []string{"subject:admin"}}, TLS: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	server := httptest.NewServer(control)
	defer server.Close()
	client, err := facts.NewAdminClient(server.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	created, status, err := client.Control(t.Context(), idp.MintIDToken("admin", time.Now().Add(time.Hour)), facts.ControlRequest{Action: "token-create"})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	record, err := hosts.Get(t.Context(), created.Token.ID)
	require.NoError(t, err)
	require.Equal(t, "pending", record.Status)
	require.Empty(t, record.Proposal.Names)
	proposal := facts.Proposal{Names: []string{"host"}, Accounts: []string{"root"}, PrincipalMode: "account-name"}
	enrolled, status, err := client.Control(t.Context(), "", facts.ControlRequest{Action: "enroll", Token: created.Token.ID, Host: &proposal})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Equal(t, record.ID, enrolled.Host.ID)
	require.Equal(t, "active", enrolled.Host.Status)
	events, err := hosts.Audit(t.Context())
	require.NoError(t, err)
	require.Equal(t, "host", events[len(events)-1].Actor)
}
