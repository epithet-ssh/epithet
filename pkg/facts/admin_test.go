package facts

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestInventoryNeverForwardsCredentialsThroughRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	client, err := NewAdminClient(source.URL, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	_, status, err := client.Control(context.Background(), "private-oidc-token", ControlRequest{Action: "list"})
	require.Error(t, err)
	require.Equal(t, 307, status)
	require.False(t, reached)
}

func TestControlUsesConfiguredEndpoint(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Equal(t, "/manage?tenant=example", r.URL.RequestURI())
		require.Equal(t, "Bearer admin-token", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()
	client, err := NewAdminClient(server.URL+"/manage?tenant=example", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for range 2 {
		_, status, err := client.Control(t.Context(), "admin-token", ControlRequest{Action: "list"})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	require.Equal(t, 2, requests)
}

func TestNewValidatesEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://inventory.example/manage", "/manage", "unix:///inventory.sock", "https://user:password@inventory.example/manage", "https://inventory.example/manage#fragment"} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := NewAdminClient(endpoint, tlsconfig.Config{})
			require.Error(t, err)
		})
	}
}

func TestUnadvertisedInventory(t *testing.T) {
	client, err := NewAdminClient("", tlsconfig.Config{})
	require.NoError(t, err)
	_, status, err := client.Control(t.Context(), "", ControlRequest{Action: "list"})
	require.ErrorContains(t, err, "CA does not advertise managed inventory")
	require.Zero(t, status)
}

func TestSCIMPagesAreBoundedAndPreserveResources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/scim/v2/Users", r.URL.Path)
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "2", r.URL.Query().Get("startIndex"))
		require.Equal(t, "100", r.URL.Query().Get("count"))
		require.Equal(t, "Bearer oidc-token", r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"startIndex":2,"itemsPerPage":1,"Resources":[{"id":"resource","externalId":"subject","urn:example:extension":{"large":9007199254740993}}]}`)
	}))
	defer server.Close()
	client, err := NewAdminClient(server.URL+"/inventory?unused=true", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	page, status, err := client.ListUsers(t.Context(), "oidc-token", 2)
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Len(t, page.Resources, 1)
	require.Contains(t, string(page.Resources[0]), "9007199254740993")
	for _, start := range []int{0, -1, int(^uint(0) >> 1)} {
		_, _, err := client.ListUsers(t.Context(), "oidc-token", start)
		require.ErrorContains(t, err, "startIndex")
	}
}

func TestSCIMPagesRejectInvalidResponsesAndRedirects(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"missing-schema", `{"totalResults":0,"startIndex":1,"itemsPerPage":0,"Resources":[]}`, 200},
		{"wrong-offset", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"startIndex":2,"itemsPerPage":1,"Resources":[{}]}`, 200},
		{"no-progress", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"startIndex":1,"itemsPerPage":0,"Resources":[]}`, 200},
		{"unbounded-count", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":0,"startIndex":1,"itemsPerPage":1000,"Resources":[]}`, 200},
		{"inconsistent-total", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":0,"startIndex":1,"itemsPerPage":1,"Resources":[{}]}`, 200},
		{"oversized", strings.Repeat(" ", MaxControlResponse+1), 200},
		{"not-scim", `{"detail":"unsupported"}`, 404},
		{"unauthorized", `{"detail":"expired"}`, 401},
		{"redirect", ``, 307},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redirected := false
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected = true }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status == 307 {
					w.Header().Set("Location", target.URL)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client, err := NewAdminClient(server.URL+"/manage", tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			_, status, err := client.ListUsers(t.Context(), "secret", 1)
			require.Error(t, err)
			require.Equal(t, tc.status, status)
			require.False(t, redirected)
		})
	}
}
