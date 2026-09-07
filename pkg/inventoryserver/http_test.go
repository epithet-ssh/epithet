package inventoryserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/inventorytest"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryserver"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (*inventory.Static, inventoryapi.ResolveRequest, *oidctest.IdP) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`users:
  - id: subject:alice
    userName: alice@example.com
    groups: [Admins]
    department: Platform
hosts:
  - name: ungrounded
  - name: empty
    accounts: []
  - name: grounded
    accounts: [root]
`), 0600))
	inv, err := inventory.NewStatic([]string{path})
	require.NoError(t, err)
	idp := oidctest.New(t)
	return inv, inventoryapi.ResolveRequest{Token: idp.MintIDToken("alice", time.Now().Add(time.Hour)), Host: "grounded"}, idp
}

func TestResolverAuthenticationAndGrounding(t *testing.T) {
	inv, req, idp := fixture(t)
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	server := inventorytest.Serve(t, inv, idp.Issuer(), pub)
	client, err := inventoryserver.NewClient(server.URL, priv, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for _, tc := range []struct {
		host     string
		accounts []string
	}{{"ungrounded", nil}, {"empty", []string{}}, {"grounded", []string{"root"}}} {
		t.Run(tc.host, func(t *testing.T) {
			request := req
			request.Host = tc.host
			result, err := client.Resolve(t.Context(), request)
			require.NoError(t, err)
			accounts, err := result.Inventory.Host.Resource.AccountList()
			require.NoError(t, err)
			require.Equal(t, tc.accounts, accounts)
			require.Equal(t, "Platform", result.Directory.User.Enterprise.Department)
			require.Equal(t, "Admins", result.Directory.User.Groups[0].Value)
			require.Equal(t, "subject:alice", result.Authentication.ID)
			data, err := json.Marshal(result)
			require.NoError(t, err)
			require.NotContains(t, string(data), req.Token)
			require.NotContains(t, string(data), `"token"`)

		})
	}
	missing := req
	missing.Token = idp.MintIDToken("missing", time.Now().Add(time.Hour))
	missing.Host = "missing"
	result, err := client.Resolve(t.Context(), missing)
	require.NoError(t, err)
	require.Nil(t, result.Directory.User)
	require.Nil(t, result.Inventory.Host)
	wrongIssuer := req
	wrongIssuer.Token = oidctest.New(t).MintIDToken("alice", time.Now().Add(time.Hour))
	_, err = client.Resolve(t.Context(), wrongIssuer)
	require.Error(t, err)
	for _, token := range []string{"", "invalid", idp.MintIDToken("alice", time.Now().Add(-time.Minute)), idp.MintIDTokenWithAudience("alice", "wrong-client", time.Now().Add(time.Hour))} {
		_, err := client.Resolve(t.Context(), inventoryapi.ResolveRequest{Token: token, Host: req.Host})
		var authErr *wire.PolicyError
		require.ErrorAs(t, err, &authErr)
		require.Equal(t, 401, authErr.StatusCode)
	}
	discovery, err := client.FetchDiscovery(t.Context())
	require.NoError(t, err)
	require.Equal(t, idp.Issuer(), discovery.Auth.Issuer)
	require.Equal(t, oidctest.ClientID, discovery.Auth.ClientID)
	require.Equal(t, "max-age=300", discovery.CacheControl)
	// Identical target/body/key with a policy audience must not grant inventory access.
	handler := server.Config.Handler
	body, err := json.Marshal(req)
	require.NoError(t, err)
	for _, aud := range []string{serviceauth.Audience, serviceauth.InventoryAudience} {
		r := httptest.NewRequest("POST", "https://inventory/v1/resolve", bytes.NewReader(body))
		signer, err := serviceauth.NewSignerFor(priv, aud)
		require.NoError(t, err)
		require.NoError(t, signer.Authorize(r, body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if aud == serviceauth.Audience {
			require.Equal(t, 403, w.Code)
		} else {
			require.Equal(t, 200, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		}
	}
	r := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, 403, w.Code)
}

func TestClientRejectsMalformedAndUnavailableInventory(t *testing.T) {
	inv, req, _ := fixture(t)
	_, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	valid, err := inventorytest.Resolver(inv).Resolve(t.Context(), inventoryapi.Authentication{ID: "subject:alice", ExpiresAt: time.Now().Add(time.Hour)}, req.Host)
	require.NoError(t, err)
	encoded, err := json.Marshal(valid)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"missing accounts", strings.Replace(string(encoded), `,"accounts":["root"]`, "", 1), 200},
		{"wrong subject", strings.Replace(string(encoded), "subject:alice", "mallory-id", 1), 200},
		{"wrong target", strings.Replace(string(encoded), `"host":"grounded"`, `"host":"other"`, 1), 200},
		{"missing revision", strings.Replace(string(encoded), `"revision":"`+inv.DirectoryRevision()+`"`, `"revision":""`, 1), 200},
		{"missing user", strings.Replace(string(encoded), `"user":`, `"unexpected":`, 1), 200},
		{"bad version", strings.Replace(string(encoded), `"version":1`, `"version":2`, 1), 200},
		{"oversized", strings.Repeat(" ", wire.MaxBodySize+1), 200},
		{"unavailable", "", 503},
		{"not JSON", "broken", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }))
			defer server.Close()
			client, err := inventoryserver.NewClient(server.URL, priv, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			_, err = client.Resolve(t.Context(), req)
			require.Error(t, err)
		})
	}
	t.Run("redirect", func(t *testing.T) {
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect destination reached") }))
		defer destination.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
		defer server.Close()
		client, err := inventoryserver.NewClient(server.URL, priv, tlsconfig.Config{Insecure: true})
		require.NoError(t, err)
		_, err = client.Resolve(context.Background(), req)
		require.Error(t, err)
	})
	t.Run("cancelled", func(t *testing.T) {
		client, err := inventoryserver.NewClient("https://inventory.invalid", priv, tlsconfig.Config{})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = client.Resolve(ctx, req)
		require.ErrorIs(t, err, context.Canceled)
	})
}
