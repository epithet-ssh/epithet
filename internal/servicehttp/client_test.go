package servicehttp_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestDiscoveredURLPolicy(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	remote, err := servicehttp.New("https://provider.example/tenant/facts", "/lookup", key, serviceauth.DirectoryAudience, tlsconfig.Config{})
	require.NoError(t, err)
	target, err := remote.Resolve("../scim/")
	require.NoError(t, err)
	require.Equal(t, "https://provider.example/scim/", target.String())
	_, err = remote.Resolve("http://provider.example/scim/")
	require.Error(t, err)
	_, err = remote.Resolve("https://provider.example:invalid/tokens?token=secret")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret")

	local, err := servicehttp.New("unix:///unused.sock", "/lookup", key, serviceauth.DirectoryAudience, tlsconfig.Config{})
	require.NoError(t, err)
	target, err = local.Resolve("/scim/")
	require.NoError(t, err)
	require.Equal(t, "http://service/scim/", target.String())
	for _, reference := range []string{"http://elsewhere/scim/", "https://service/scim/"} {
		_, err = local.Resolve(reference)
		require.Error(t, err)
	}
}
