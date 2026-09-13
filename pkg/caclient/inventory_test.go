package caclient

import (
	"fmt"
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
