package inventoryserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/inventorytest"
	"github.com/epithet-ssh/epithet/pkg/facts"
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
    organization: Example
    userType: employee
hosts:
  - names: [ungrounded]
  - names: [empty]
    accounts: []
  - names: [grounded]
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
			require.Equal(t, request.Host, result.Target)
			accounts, err := result.Inventory.Host.AccountList()
			require.NoError(t, err)
			require.Equal(t, tc.accounts, accounts)
			require.Equal(t, "Platform", result.Directory.User.Department)
			require.Equal(t, "Example", result.Directory.User.Organization)
			require.Equal(t, "employee", result.Directory.User.UserType)
			require.Equal(t, "Admins", result.Directory.User.Groups[0])
			require.Equal(t, "subject:alice", result.Authentication.ID)
			data, err := json.Marshal(result)
			require.NoError(t, err)
			require.NotContains(t, string(data), req.Token)
			require.NotContains(t, string(data), `"token"`)
			require.NotContains(t, string(data), "schemas")
			require.NotContains(t, string(data), "urn:")
			require.Contains(t, string(data), `"groups":["Admins"]`)

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
		r := httptest.NewRequest("POST", "https://inventory/", bytes.NewReader(body))
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
	r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, 403, w.Code)
}

func TestClientRejectsMalformedAndUnavailableInventory(t *testing.T) {
	inv, req, _ := fixture(t)
	_, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	valid, err := inventorytest.Resolver(inv).Resolve(t.Context(), facts.Authentication{ID: "subject:alice", ExpiresAt: time.Now().Add(time.Hour)}, req.Host)
	require.NoError(t, err)
	encoded, err := json.Marshal(valid)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "resolvedAt")
	require.NotContains(t, string(encoded), `"resource"`)
	require.Contains(t, string(encoded), `"target":"grounded"`)
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"missing active", strings.Replace(string(encoded), `,"active":true`, "", 1), 200},
		{"empty group", strings.Replace(string(encoded), `"groups":["Admins"]`, `"groups":[""]`, 1), 200},
		{"legacy group objects", strings.Replace(string(encoded), `"groups":["Admins"]`, `"groups":[{"value":"Admins","display":"Admins"}]`, 1), 200},
		{"missing names", strings.Replace(string(encoded), `"names":["grounded"]`, `"name":"grounded"`, 1), 200},
		{"empty names", strings.Replace(string(encoded), `"names":["grounded"]`, `"names":[]`, 1), 200},
		{"duplicate names", strings.Replace(string(encoded), `"names":["grounded"]`, `"names":["grounded","grounded"]`, 1), 200},
		{"target not in names", strings.Replace(string(encoded), `"names":["grounded"]`, `"names":["other"]`, 1), 200},
		{"missing accounts", strings.Replace(string(encoded), `,"accounts":["root"]`, "", 1), 200},
		{"wrong subject", strings.Replace(string(encoded), "subject:alice", "mallory-id", 1), 200},
		{"wrong target", strings.Replace(string(encoded), `"target":"grounded"`, `"target":"other"`, 1), 200},
		{"missing revision", strings.Replace(string(encoded), `"revision":"`+inv.DirectoryRevision()+`"`, `"revision":""`, 1), 200},
		{"missing user", strings.Replace(string(encoded), `"user":`, `"unexpected":`, 1), 200},
		{"bad version", strings.Replace(string(encoded), `"version":2`, `"version":1`, 1), 200},
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
		_, err = client.FetchDiscovery(t.Context())
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

func TestConfiguredEndpointThroughProxy(t *testing.T) {
	inv, req, idp := fixture(t)
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	backend := inventorytest.Serve(t, inv, idp.Issuer(), pub)
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	proxy.Transport = backend.Client().Transport
	for _, path := range []string{"", "/", "/internal/inventory", "/internal/inventory/", "/internal/inventory%20lookup"} {
		t.Run(path, func(t *testing.T) {
			wantPath := path
			if wantPath == "" {
				wantPath = "/"
			}
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != wantPath {
					t.Errorf("request path = %q, want configured endpoint %q", r.RequestURI, wantPath)
					http.NotFound(w, r)
					return
				}
				proxy.ServeHTTP(w, r)
			}))
			defer front.Close()
			client, err := inventoryserver.NewClient(front.URL+path, priv, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			result, err := client.Resolve(t.Context(), req)
			require.NoError(t, err)
			require.Equal(t, req.Host, result.Target)
			discovery, err := client.FetchDiscovery(t.Context())
			require.NoError(t, err)
			require.Equal(t, idp.Issuer(), discovery.Auth.Issuer)
			require.Equal(t, "max-age=300", discovery.CacheControl)
		})
	}
}

func TestInventoryUnixEndpoint(t *testing.T) {
	inv, req, idp := fixture(t)
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	backend := inventorytest.Serve(t, inv, idp.Issuer(), pub)
	// Keep below macOS's Unix socket path limit.
	dir, err := os.MkdirTemp("/tmp", "inventory-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "inventory.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/" {
			t.Errorf("Unix request path = %q, want /", r.RequestURI)
			http.NotFound(w, r)
			return
		}
		backend.Config.Handler.ServeHTTP(w, r)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	client, err := inventoryserver.NewClient("unix://"+path, priv, tlsconfig.Config{})
	require.NoError(t, err)
	result, err := client.Resolve(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, req.Host, result.Target)
	discovery, err := client.FetchDiscovery(t.Context())
	require.NoError(t, err)
	require.Equal(t, idp.Issuer(), discovery.Auth.Issuer)
}

func TestInventoryEndpointRequestBinding(t *testing.T) {
	inv, req, idp := fixture(t)
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	backend := inventorytest.Serve(t, inv, idp.Issuer(), pub)
	signer, err := serviceauth.NewSignerFor(priv, serviceauth.InventoryAudience)
	require.NoError(t, err)
	body, err := json.Marshal(req)
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"valid", func(*http.Request) {}, http.StatusOK},
		{"method", func(r *http.Request) { r.Method = "GET" }, http.StatusForbidden},
		{"path", func(r *http.Request) { r.URL.Path = "/other" }, http.StatusForbidden},
		{"host", func(r *http.Request) { r.Host = "other" }, http.StatusForbidden},
		{"body", func(r *http.Request) { r.Body = http.NoBody }, http.StatusForbidden},
		{"query", func(r *http.Request) { r.URL.RawQuery = "operation=other" }, http.StatusNotFound},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://inventory/internal/inventory", bytes.NewReader(body))
			require.NoError(t, signer.Authorize(r, body))
			tc.mutate(r)
			w := httptest.NewRecorder()
			backend.Config.Handler.ServeHTTP(w, r)
			require.Equal(t, tc.status, w.Code)
		})
	}
	for _, endpoint := range []string{"https://inventory/?operation=other", "https://inventory/?"} {
		_, err := inventoryserver.NewClient(endpoint, priv, tlsconfig.Config{})
		require.ErrorContains(t, err, "query")
	}
	r := httptest.NewRequest("DELETE", "https://inventory/", nil)
	require.NoError(t, signer.Authorize(r, nil))
	w := httptest.NewRecorder()
	backend.Config.Handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}
