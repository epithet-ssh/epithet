package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestServerPrincipalModePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		args   []string
		want   inventory.PrincipalMode
	}{
		{
			name:   "unspecified retains inventory default",
			config: "",
			want:   inventory.EpithetPrincipalV1,
		},
		{
			name:   "inherits hashed inventory configuration",
			config: "principal-mode = \"epithet-principal-v1\"\n",
			want:   inventory.EpithetPrincipalV1,
		},
		{
			name:   "shared configuration selects account-name",
			config: "principal-mode = \"account-name\"\n",
			want:   inventory.AccountNamePrincipals,
		},
		{
			name:   "shared configuration selects destination-bound principals",
			config: "principal-mode = \"epithet-principal-v1\"\n",
			want:   inventory.EpithetPrincipalV1,
		},
		{
			name:   "CLI compatibility overrides shared configuration",
			config: "principal-mode = \"epithet-principal-v1\"\n",
			args:   []string{"--principal-mode", "account-name"},
			want:   inventory.AccountNamePrincipals,
		},
		{
			name:   "CLI hashed overrides shared configuration",
			config: "principal-mode = \"account-name\"\n",
			args:   []string{"--principal-mode", "epithet-principal-v1"},
			want:   inventory.EpithetPrincipalV1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			require.NoError(t, os.WriteFile(path, []byte(tc.config), 0o600))
			parse := func(args []string) (*ServerCLI, *InventoryCLI) {
				t.Helper()
				var root struct {
					Config    kong.ConfigFlag `name:"config"`
					Server    ServerCLI       `cmd:"server"`
					Inventory InventoryCLI    `cmd:"inventory"`
				}
				parser, err := kong.New(&root, kong.Configuration(loadCLIConfig))
				require.NoError(t, err)
				_, err = parser.Parse(args)
				require.NoError(t, err)
				return &root.Server, &root.Inventory
			}

			server, _ := parse(append([]string{"--config", path, "server"}, tc.args...))
			// Reparse the actual subprocess arguments with the same config, as
			// the combined server does, without starting CA or OIDC services.
			_, inventory := parse(server.inventoryArgs([]string{"--config", path}, "/tmp/inventory.sock", "unused-key"))
			require.Equal(t, string(tc.want), inventory.PrincipalMode)
		})
	}
}

func TestServerRejectsUnknownPrincipalModeBeforeStartingServices(t *testing.T) {
	server := &ServerCLI{PrincipalMode: "mystery"}
	err := server.Run(nil, tlsconfig.Config{})
	require.ErrorContains(t, err, `unknown principal mode "mystery"`)
}

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
