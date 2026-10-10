package inventorytest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

type Facts struct {
	*httptest.Server
	Identity oidc.Config
}

func (f *Facts) CAOption() ca.Option {
	return ca.WithFacts(f.URL+"/directory", f.URL+"/inventory", f.Identity, wire.AuthConfig{Issuer: f.Identity.Issuer, ClientID: f.Identity.ClientID}, tlsconfig.Config{Insecure: true})
}
func ServeFacts(t *testing.T, inv *inventory.Static, issuer string, key sshcert.RawPublicKey) *Facts {
	return ServeFactsWithSources(t, inv, inv, oidc.Config{Issuer: issuer, ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}}, key)
}
func ServeFactsWithConfig(t *testing.T, inv *inventory.Static, cfg oidc.Config, key sshcert.RawPublicKey) *Facts {
	return ServeFactsWithSources(t, inv, inv, cfg, key)
}
func ServeFactsWithSources(t *testing.T, users directory.Directory, hosts inventory.Hosts, cfg oidc.Config, key sshcert.RawPublicKey) *Facts {
	t.Helper()
	dir, err := facts.Handler(users, nil, key, "")
	require.NoError(t, err)
	inv, err := facts.Handler(nil, hosts, key, "")
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.Handle("/directory/lookup", dir)
	mux.Handle("/inventory/lookup", inv)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return &Facts{server, cfg}
}
