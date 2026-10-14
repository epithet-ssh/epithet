package control_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/control"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/test/controltest"
	"github.com/epithet-ssh/epithet/test/oidctest"
	"github.com/stretchr/testify/require"
)

func TestSCIMOIDCWithoutProvisioningSecret(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer store.Close()
	var member string
	for _, id := range []string{"admin", "member", "inventory-admin", "disabled"} {
		user, err := store.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject:" + id}, ExternalID: "subject:" + id, UserName: id, Active: id != "disabled"}, directory.NewAuditEvent(t.Context(), "create", "subject:"+id))
		require.NoError(t, err)
		if id == "member" {
			member = user.ID
		}
	}
	_, err = store.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-ops"}, DisplayName: "ops", MemberIDs: []string{member}}, directory.NewAuditEvent(t.Context(), "create", "group-ops"))
	require.NoError(t, err)
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(t.Context(), oidc.ValidatorConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	f := controltest.New(t, store, store, nil, control.Config{Validator: validator, DirectoryAdmins: control.Admins{Users: []string{"subject:admin", "subject:disabled"}, Groups: []string{"ops"}}, InventoryAdmins: control.Admins{Users: []string{"subject:inventory-admin"}}})
	request := func(method, path, body, token, match string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("If-Match", match)
		rec := httptest.NewRecorder()
		f.Control.ServeHTTP(rec, req)
		return rec
	}
	for _, tc := range []struct {
		id     string
		status int
	}{{"admin", 200}, {"member", 200}, {"inventory-admin", 403}, {"disabled", 403}, {"missing", 403}} {
		for _, resource := range []string{"Users", "Groups"} {
			response := request("GET", "/scim/v2/"+resource+"?count=1", "", idp.MintIDToken(tc.id, time.Now().Add(time.Hour)), "")
			require.Equal(t, tc.status, response.Code, response.Body.String())
		}
	}
	for _, token := range []string{"", "not-an-oidc-token", idp.MintIDToken("admin", time.Now().Add(-time.Hour))} {
		response := request("GET", "/scim/v2/Users", "", token, "")
		require.Equal(t, 401, response.Code)
		require.Equal(t, `Bearer realm="scim"`, response.Header().Get("WWW-Authenticate"))
		require.Contains(t, response.Body.String(), "urn:ietf:params:scim:api:messages:2.0:Error")
	}
	token := idp.MintIDToken("admin", time.Now().Add(time.Hour))
	created := request("POST", "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"subject:new","userName":"new","active":true}`, token, "")
	require.Equal(t, 201, created.Code, created.Body.String())
	var user struct{ ID string }
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &user))
	path := "/scim/v2/Users/" + user.ID
	replaced := request("PUT", path, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"subject:new","userName":"renamed","active":true}`, token, created.Header().Get("ETag"))
	require.Equal(t, 200, replaced.Code, replaced.Body.String())
	stale := request("DELETE", path, "", token, created.Header().Get("ETag"))
	require.Equal(t, 412, stale.Code)
	deleted := request("DELETE", path, "", token, replaced.Header().Get("ETag"))
	require.Equal(t, 204, deleted.Code)
	events, _, err := store.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	actions := []string{}
	for _, event := range events {
		if event.Actor == "subject:admin" {
			actions = append(actions, event.Action)
		}
	}
	require.Equal(t, []string{"create", "replace", "delete"}, actions)
	// Neither the CA reader key nor an unsigned bearer grants private SCIM access.
	signer, err := serviceauth.NewSignerFor(f.CAKey, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	req, err := http.NewRequest("GET", f.DirectoryURL+"/scim/v2/Users", nil)
	require.NoError(t, err)
	require.NoError(t, signer.AuthorizeActor(req, nil, "subject:admin"))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 403, resp.StatusCode)
}

func TestGroupListingThroughControlPaginatesManagedGroups(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	user, err := store.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "alice"}, UserName: "alice", Active: true}, directory.NewAuditEvent(t.Context(), "create", "alice"))
	require.NoError(t, err)
	for n := range 101 {
		_, err := store.CreateGroup(t.Context(), directory.ManagedGroup{
			Metadata:    directory.Metadata{ID: fmt.Sprintf("group-%03d", n)},
			DisplayName: "ops", MemberIDs: []string{user.ID},
		}, directory.NewAuditEvent(t.Context(), "create", fmt.Sprintf("group-%03d", n)))
		require.NoError(t, err)
	}
	f := controltest.New(t, store, store, nil, control.Config{SCIMToken: "provisioning-secret"})
	client, err := facts.NewAdminClient(f.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for _, tc := range []struct{ start, count int }{{1, 100}, {101, 1}, {102, 0}} {
		page, status, err := client.ListGroups(t.Context(), "provisioning-secret", tc.start)
		require.NoError(t, err)
		require.Equal(t, 200, status)
		require.Equal(t, 101, page.TotalResults)
		require.Equal(t, tc.start, page.StartIndex)
		require.Len(t, page.Resources, tc.count)
		for i, raw := range page.Resources {
			var group struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
				Members     []struct {
					Value string `json:"value"`
				} `json:"members"`
			}
			require.NoError(t, json.Unmarshal(raw, &group))
			require.Equal(t, fmt.Sprintf("group-%03d", tc.start-1+i), group.ID)
			require.Equal(t, "ops", group.DisplayName)
			require.Len(t, group.Members, 1)
			require.Equal(t, user.ID, group.Members[0].Value)
		}
	}
}

type unavailableIdentity struct{}

func (unavailableIdentity) Validate(context.Context, string) (*oidc.Claims, error) {
	return nil, oidc.ErrUnavailable
}

func TestSCIMSecretIndependentOfOIDCAndDiscovery(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer store.Close()
	f := controltest.New(t, store, store, nil, control.Config{Validator: unavailableIdentity{}, SCIMToken: "secret"})
	for _, tc := range []struct {
		token  string
		status int
	}{{"secret", 200}, {"oidc-token", 503}, {"", 401}} {
		req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		rec := httptest.NewRecorder()
		f.Control.ServeHTTP(rec, req)
		require.Equal(t, tc.status, rec.Code, rec.Body.String())
	}
	// An external provider needs no /manage or /actor endpoint and no backend URL.
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(pub, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, err := verifier.VerifyActor(r, nil)
		require.NoError(t, err)
		if r.Method == "OPTIONS" {
			require.Equal(t, "/facts", r.URL.Path)
			require.Empty(t, actor)
			w.Header().Set("Link", `</provision/>; rel="`+wire.RelSCIM+`"`)
			w.WriteHeader(204)
			return
		}
		require.Equal(t, "scim", actor)
		require.Equal(t, "/provision/Users", r.URL.Path)
		w.Header().Set("Content-Type", "application/scim+json")
		w.Write([]byte(`{"Resources":[]}`))
	}))
	defer provider.Close()
	server, err := control.New(control.Config{Key: key, DirectoryURL: provider.URL + "/facts", Validator: unavailableIdentity{}, SCIMToken: "secret", TLS: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code, rec.Body.String())
}
