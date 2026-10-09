package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestCAChildIdentityConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("oidc-issuer = \"https://issuer.example\"\noidc-client-id = \"app\"\noidc-user-id-claim = \"oid\"\n"), 0600))
	auth, err := caChildOIDC([]string{"--config", path, "ca", "--directory", "http://directory", "--inventory", "http://inventory"})
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example", auth.Issuer)
	require.Equal(t, "app", auth.ClientID)
	require.Equal(t, "oid", auth.UserIDClaim)
}

func TestServerOwnsChildListenersAndInventoryRouting(t *testing.T) {
	// Combined topology must override standalone command configuration, including
	// disabling a configured inventory route when the child has no management endpoint.
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(`listen = ":9999"
control-public = "https://old.example/manage"
ca-backend = "unix:///tmp/old-ca.sock"
control-backend = "unix:///tmp/old-control.sock"
`), 0600))
	for _, managed := range []bool{true, false} {
		var root struct {
			Config kong.ConfigFlag `name:"config"`
			CA     CACLI           `cmd:"ca"`
			Router RouterCLI       `cmd:"router"`
		}
		parse := func(args []string) {
			t.Helper()
			parser, err := kong.New(&root, kong.Configuration(loadCLIConfig))
			require.NoError(t, err)
			_, err = parser.Parse(args)
			require.NoError(t, err)
		}
		server := ServerCLI{Listen: "127.0.0.1:8080", CAKey: "/tmp/ca.key"}
		globals := []string{"--config", path}
		parse(server.caArgs(globals, "/tmp/ca.sock", "/tmp/directory.sock", "/tmp/inventory.sock", managed))
		require.Equal(t, "unix:///tmp/ca.sock", root.CA.Listen)
		require.Equal(t, "unix:///tmp/directory.sock", root.CA.Directory)
		require.Equal(t, "unix:///tmp/inventory.sock", root.CA.Inventory)
		if managed {
			require.Equal(t, "inventory", root.CA.ControlPublicURL)
		} else {
			require.Empty(t, root.CA.ControlPublicURL)
		}
		parse(server.routerArgs(globals, "/tmp/ca.sock", "/tmp/inventory.sock", managed))
		require.Equal(t, server.Listen, root.Router.Listen)
		require.Equal(t, "unix:///tmp/ca.sock", root.Router.CA)
		if managed {
			require.Equal(t, "unix:///tmp/inventory.sock", root.Router.Control)
		} else {
			require.Empty(t, root.Router.Control)
		}
	}
}
