// Package inventorytest builds real inventory services for integration tests.
package inventorytest

import (
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryserver"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func Resolver(inv *inventory.Static) *inventoryserver.Resolver {
	return &inventoryserver.Resolver{Directory: inv, Hosts: inv, DirectoryRevision: inv.DirectoryRevision(), InventoryRevision: inv.InventoryRevision()}
}
func Serve(t *testing.T, inv *inventory.Static, issuer string, key sshcert.RawPublicKey) *httptest.Server {
	t.Helper()
	return ServeWithConfig(t, inv, oidc.Config{Issuer: issuer, ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}}, key)
}
func ServeWithConfig(t *testing.T, inv *inventory.Static, cfg oidc.Config, key sshcert.RawPublicKey) *httptest.Server {
	t.Helper()
	validator, err := oidc.NewValidator(t.Context(), cfg)
	require.NoError(t, err)
	handler, err := inventoryserver.NewHandler(inventoryserver.Config{CAPublicKey: key, Resolver: Resolver(inv), Validator: validator, Discovery: &wire.Discovery{Auth: &wire.AuthConfig{Issuer: cfg.Issuer, ClientID: cfg.ClientID}}})
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}
