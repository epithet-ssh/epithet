package inventoryclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestInventoryNeverForwardsCredentialsThroughRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	client, err := New(source.URL, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	_, status, err := client.Control(context.Background(), "private-oidc-token", inventoryapi.ControlRequest{Action: "list"})
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
	client, err := New(server.URL+"/manage?tenant=example", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for range 2 {
		_, status, err := client.Control(t.Context(), "admin-token", inventoryapi.ControlRequest{Action: "list"})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	require.Equal(t, 2, requests)
}

func TestNewValidatesEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://inventory.example/manage", "/manage", "unix:///inventory.sock", "https://user:password@inventory.example/manage", "https://inventory.example/manage#fragment"} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := New(endpoint, tlsconfig.Config{})
			require.Error(t, err)
		})
	}
}

func TestUnadvertisedInventory(t *testing.T) {
	client, err := New("", tlsconfig.Config{})
	require.NoError(t, err)
	_, status, err := client.Control(t.Context(), "", inventoryapi.ControlRequest{Action: "list"})
	require.ErrorContains(t, err, "CA does not advertise managed inventory")
	require.Zero(t, status)
}
