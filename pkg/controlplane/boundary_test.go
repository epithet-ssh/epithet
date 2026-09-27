package controlplane_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/controltest"
	"github.com/epithet-ssh/epithet/pkg/controlplane"
	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/factservice"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
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
	hosts, err := inventory.OpenManaged(t.TempDir(), nil)
	require.NoError(t, err)
	defer hosts.Close()
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(t.Context(), oidc.Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	f := controltest.New(t, users, users, hosts, controlplane.Config{Validator: validator, DirectoryAdmins: controlplane.Admins{Users: []string{"subject:directory-admin"}}, InventoryAdmins: controlplane.Admins{Users: []string{"subject:inventory-admin"}}, SCIMToken: "provisioning-secret"})
	client, err := inventoryclient.New(f.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for _, id := range []string{"directory-admin", "inventory-admin"} {
		token := idp.MintIDToken(id, time.Now().Add(time.Hour))
		for _, action := range []string{"directory-users", "list"} {
			_, status, err := client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: action})
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
	data := []byte(`{"request":{"action":"token-create"}}`)
	for _, key := range []sshcert.RawPrivateKey{f.CAKey, f.ControlKey} {
		private, err := serviceauth.NewClient(f.InventoryURL, key, serviceauth.InventoryAudience, tlsconfig.Config{Insecure: true})
		require.NoError(t, err)
		resp, err := private.Do(t.Context(), "POST", "/manage", nil, data, "subject:inventory-admin")
		require.NoError(t, err)
		resp.Body.Close()
		if key == f.CAKey {
			require.Equal(t, 403, resp.StatusCode)
		} else {
			require.Equal(t, 200, resp.StatusCode)
		}
	}
	events, err := hosts.Audit()
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
	hosts, err := inventory.OpenManaged(t.TempDir(), nil)
	require.NoError(t, err)
	defer hosts.Close()
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(pub, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	custom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, verifier.Verify(r, nil))
		require.Equal(t, "/lookup", r.URL.Path)
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "subject:admin", r.URL.Query().Get("id"))
		json.NewEncoder(w).Encode(factservice.User{ID: "subject:admin"})
	}))
	defer custom.Close()
	handler, err := (&controlplane.Backend{Store: hosts}).Handler(pub)
	require.NoError(t, err)
	backend := httptest.NewServer(handler)
	defer backend.Close()
	control, err := controlplane.New(controlplane.Config{Key: key, DirectoryURL: custom.URL, InventoryBackendURL: backend.URL, Validator: validator, InventoryAdmins: controlplane.Admins{Users: []string{"subject:admin"}}, TLS: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	server := httptest.NewServer(control)
	defer server.Close()
	client, err := inventoryclient.New(server.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	created, status, err := client.Control(t.Context(), idp.MintIDToken("admin", time.Now().Add(time.Hour)), inventoryapi.ControlRequest{Action: "token-create"})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	record, err := hosts.Get(created.Token.ID)
	require.NoError(t, err)
	require.Equal(t, "pending", record.Status)
	require.Empty(t, record.Proposal.Names)
	proposal := inventoryapi.Proposal{Names: []string{"host"}, Accounts: []string{"root"}, PrincipalMode: "account-name"}
	enrolled, status, err := client.Control(t.Context(), "", inventoryapi.ControlRequest{Action: "enroll", Token: created.Token.ID, Host: &proposal})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Equal(t, record.ID, enrolled.Host.ID)
	require.Equal(t, "active", enrolled.Host.Status)
	events, err := hosts.Audit()
	require.NoError(t, err)
	require.Equal(t, "host", events[len(events)-1].Actor)
}
