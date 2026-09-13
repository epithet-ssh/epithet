package caclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestInventoryDiscoverySeparateOriginAndTLS(t *testing.T) {
	root := &RootResponse{FinalURL: "https://ca.example/prefix/", Links: []string{`<https://inventory.example/manage>; rel="https://epithet.dev/rel/inventory"`}}
	target, err := InventoryURL(root, tlsconfig.Config{})
	require.NoError(t, err)
	require.Equal(t, "https://inventory.example/manage", target)
	root.Links = []string{`<inventory>; rel="https://epithet.dev/rel/inventory"`}
	target, err = InventoryURL(root, tlsconfig.Config{})
	require.NoError(t, err)
	require.Equal(t, "https://ca.example/prefix/inventory", target)
	root.Links = []string{`<inventory?route=hosts>; rel="https://epithet.dev/rel/inventory"`}
	target, err = InventoryURL(root, tlsconfig.Config{})
	require.NoError(t, err)
	require.Equal(t, "https://ca.example/prefix/inventory?route=hosts", target)
	for _, bad := range []string{"http://inventory.example/manage", "https://user:password@example/manage", "file:///tmp/socket"} {
		root.Links = []string{fmt.Sprintf(`<%s>; rel="https://epithet.dev/rel/inventory"`, bad)}
		_, err = InventoryURL(root, tlsconfig.Config{})
		require.Error(t, err)
	}
	root.Links = nil
	target, err = InventoryURL(root, tlsconfig.Config{})
	require.NoError(t, err)
	require.Empty(t, target)
}

func TestDiscoveryUsesOneBootstrapForAuthAndInventory(t *testing.T) {
	roots := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/prefix/":
			roots++
			w.Header().Add("Link", `<auth>; rel="https://epithet.dev/rel/auth"`)
			w.Header().Add("Link", `<manage?route=hosts>; rel="https://epithet.dev/rel/inventory"`)
		case "/prefix/auth":
			fmt.Fprint(w, `{"auth":{"issuer":"https://issuer.example","client_id":"client"}}`)
		default:
			t.Errorf("unexpected discovery path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New([]CAEndpoint{{URL: server.URL + "/prefix/"}}, WithTLSConfig(tlsconfig.Config{Insecure: true}))
	require.NoError(t, err)
	discovery, err := client.GetDiscovery(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, roots)
	require.Equal(t, server.URL+"/prefix/", discovery.PublicCAURL)
	require.Equal(t, server.URL+"/prefix/manage?route=hosts", discovery.InventoryURL)
	require.Equal(t, "https://issuer.example", discovery.Auth.Issuer)
}
