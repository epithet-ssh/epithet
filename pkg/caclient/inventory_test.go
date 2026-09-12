package caclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
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
	for _, bad := range []string{"http://inventory.example/manage", "https://user:password@example/manage", "file:///tmp/socket", "https://example/manage?query=yes"} {
		root.Links = []string{fmt.Sprintf(`<%s>; rel="https://epithet.dev/rel/inventory"`, bad)}
		_, err = InventoryURL(root, tlsconfig.Config{})
		require.Error(t, err)
	}
	root.Links = nil
	target, err = InventoryURL(root, tlsconfig.Config{})
	require.NoError(t, err)
	require.Empty(t, target)
}
func TestInventoryNeverForwardsCredentialsThroughRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	_, status, err := DoInventory(context.Background(), source.Client(), source.URL, "private-oidc-token", inventoryapi.ControlRequest{Action: "list"})
	require.Error(t, err)
	require.Equal(t, 307, status)
	require.False(t, reached)
}
