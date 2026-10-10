package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestPublicInventoryURLValidation(t *testing.T) {
	for _, value := range []string{"", "inventory", "/manage?route=inventory", "https://inventory.example/manage?route=hosts"} {
		require.NoError(t, validatePublicInventoryURL(value, tlsconfig.Config{}), value)
	}
	for _, tc := range []struct{ value, reason string }{
		{"https://user:password@inventory.example/manage", "embedded credentials"},
		{"inventory#host", "fragment"},
		{"inventory>\r\nInjected: value", "Link header"},
		{"file:///tmp/inventory", "HTTP(S)"},
		{"https:///manage", "HTTP(S)"},
	} {
		require.ErrorContains(t, validatePublicInventoryURL(tc.value, tlsconfig.Config{}), tc.reason)
	}
	require.Error(t, validatePublicInventoryURL("http://inventory.example/manage", tlsconfig.Config{}))
	require.NoError(t, validatePublicInventoryURL("http://inventory.example/manage", tlsconfig.Config{Insecure: true}))
}

func TestCAUserIDClaimConfigAndCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("oidc-issuer = \"https://issuer.example\"\noidc-user-id-claim = \"directory_id\"\n"), 0600))
	for _, override := range []bool{false, true} {
		var root struct {
			CA CACLI `cmd:"ca"`
		}
		parser, err := kong.New(&root, kong.Configuration(loadCLIConfig, path))
		require.NoError(t, err)
		args := []string{"ca", "--directory", "http://directory", "--inventory", "http://inventory"}
		want := "directory_id"
		if override {
			args = append(args, "--oidc-user-id-claim", "oid")
			want = "oid"
		}
		_, err = parser.Parse(args)
		require.NoError(t, err)
		require.Equal(t, want, root.CA.OIDC.UserIDClaim)
	}
}

func TestCAIdentityModeConfigPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("oidc-identity-mode = \"verified-email\"\n"), 0600))
	for _, tc := range []struct {
		name, env, flag string
		want            oidc.IdentityMode
	}{
		{"toml", "", "", oidc.VerifiedEmail},
		{"toml-over-env", "stable-id", "", oidc.VerifiedEmail},
		{"env-only", "stable-id", "", oidc.StableID},
		{"flag", "stable-id", "verified-email", oidc.VerifiedEmail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("EPITHET_OIDC_IDENTITY_MODE", tc.env)
			var root struct {
				CA CACLI `cmd:"ca"`
			}
			var options []kong.Option
			if tc.name != "env-only" {
				options = append(options, kong.Configuration(loadCLIConfig, path))
			}
			parser, err := kong.New(&root, options...)
			require.NoError(t, err)
			args := []string{"ca", "--directory", "http://directory", "--inventory", "http://inventory"}
			if tc.flag != "" {
				args = append(args, "--oidc-identity-mode", tc.flag)
			}
			_, err = parser.Parse(args)
			require.NoError(t, err)
			mode, _, err := oidc.ResolveIdentity("", root.CA.OIDC.IdentityMode, "")
			require.NoError(t, err)
			require.Equal(t, tc.want, mode)
		})
	}
}
