package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestStaticDirectoryRecoveryIgnoresDatabaseAndToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static.yaml")
	require.NoError(t, os.WriteFile(path, []byte("users:\n - id: admin-sub\n   userName: admin\n"), 0600))
	c := InventoryCLI{Check: true, DirectorySource: "static", StateDir: "/unavailable/state", SCIMTokenFile: "/missing/secret", Static: []string{path}, OIDC: InventoryOIDCConfig{Issuer: "https://issuer.example"}}
	require.NoError(t, c.runServer(slog.New(slog.NewTextHandler(io.Discard, nil)), tlsconfig.Config{}))
	c.DirectorySource = "scim"
	require.ErrorContains(t, c.runServer(slog.New(slog.NewTextHandler(io.Discard, nil)), tlsconfig.Config{}), "reading SCIM token file")
	inv, e := inventory.NewStatic([]string{path}, inventory.WithoutUsers())
	require.NoError(t, e)
	u, _, e := inv.LookupUser(t.Context(), "admin-sub")
	require.NoError(t, e)
	require.Nil(t, u)
}
func TestSCIMAloneEnablesInventoryAdministration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("inventory:\n  directory-source: scim\n  state-dir: /tmp/state\n  scim-token-file: /tmp/scim.token\n"), 0600))
	managed, e := inventoryChildManaged([]string{"--config", path, "inventory"})
	require.NoError(t, e)
	require.True(t, managed)
}

func TestSCIMServerTokenConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, literal, file, source, wantError string }{
		{name: "literal", literal: "literal-provisioning-token"},
		{name: "file", file: "file-provisioning-token\n"},
		{name: "both", literal: "literal-provisioning-token", file: "file-provisioning-token", wantError: "use either scim-token or scim-token-file"},
		{name: "missing", wantError: "requires scim-token or scim-token-file"},
		{name: "invalid literal", literal: "not a token", wantError: "without whitespace"},
		{name: "empty file", file: "\n", wantError: "nonempty bearer token"},
		{name: "static ignores credentials", source: "static", literal: "unused", file: "unused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			static := filepath.Join(dir, "hosts.yaml")
			require.NoError(t, os.WriteFile(static, []byte("hosts: []\n"), 0600))
			source := tc.source
			if source == "" {
				source = "scim"
			}
			config := map[string]any{"inventory": map[string]any{"directory-source": source, "state-dir": filepath.Join(dir, "state"), "scim-token": tc.literal, "static": []string{static}, "oidc": map[string]any{"issuer": "https://issuer.example"}}}
			if tc.file != "" {
				tokenPath := filepath.Join(dir, "token")
				require.NoError(t, os.WriteFile(tokenPath, []byte(tc.file), 0600))
				config["inventory"].(map[string]any)["scim-token-file"] = tokenPath
			}
			data, err := yaml.Marshal(config)
			require.NoError(t, err)
			path := filepath.Join(dir, "config.yaml")
			require.NoError(t, os.WriteFile(path, data, 0600))
			var root struct {
				Inventory InventoryCLI `cmd:"inventory"`
			}
			parser, err := kong.New(&root, kong.Configuration(kongyaml.Loader, path))
			require.NoError(t, err)
			_, err = parser.Parse([]string{"inventory", "--check"})
			require.NoError(t, err)
			err = root.Inventory.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{})
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
			}
			if source == "static" {
				require.NoDirExists(t, root.Inventory.StateDir)
			}
		})
	}
}

func TestServiceStatePathsAndSourceSelection(t *testing.T) {
	base, err := config.SystemStateDir()
	require.NoError(t, err)
	for _, name := range []string{filepath.Join("directory", "directory.db"), "inventory"} {
		path, err := serviceStatePath("", name)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(base, name), path)
		path, err = serviceStatePath("custom/state", name)
		require.NoError(t, err)
		require.Equal(t, filepath.Join("custom/state", name), path)
	}
	for _, directorySource := range []string{"static", "scim"} {
		for _, source := range []string{"", "static", "managed"} {
			t.Run(directorySource+"/"+source, func(t *testing.T) {
				dir := t.TempDir()
				hosts := filepath.Join(dir, "hosts.yaml")
				state := filepath.Join(dir, "state")
				require.NoError(t, os.WriteFile(hosts, []byte("hosts: []\n"), 0600))
				c := InventoryCLI{Check: true, Static: []string{hosts}, StateDir: state, InventorySource: source, DirectorySource: directorySource, SCIMToken: "provisioning-token", OIDC: InventoryOIDCConfig{Issuer: "https://issuer.example"}}
				// Service startup must not consult client profile/socket configuration.
				c.ManagementCLI = ManagementCLI{Name: "invalid/profile", Broker: "/missing/agent.sock"}
				require.NoError(t, c.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{}))
				if source == "managed" {
					require.DirExists(t, filepath.Join(state, "inventory", "records"))
				} else {
					require.NoDirExists(t, filepath.Join(state, "inventory"))
				}
				if directorySource == "scim" {
					require.FileExists(t, filepath.Join(state, "directory", "directory.db"))
				} else {
					require.NoDirExists(t, filepath.Join(state, "directory"))
					if source != "managed" {
						require.NoDirExists(t, state)
					}
				}
			})
		}
	}
}

func TestServiceConfigDoesNotRequireAgentAndDefaultPathsDoNotEnableStorage(t *testing.T) {
	for _, settings := range []struct {
		yaml    string
		managed bool
	}{
		{"", false},
		{"  state-dir: /unavailable/host-state\n", false},
		{"  inventory-source: managed\n", true},
		{"  directory-source: scim\n", true},
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		// An invalid agent profile must not affect server configuration parsing.
		require.NoError(t, os.WriteFile(path, []byte("agent:\n  name: invalid/profile\ninventory:\n  listen: 127.0.0.1:9998\n"+settings.yaml), 0600))
		enabled, err := inventoryChildManaged([]string{"--config", path, "inventory"})
		require.NoError(t, err)
		require.Equal(t, settings.managed, enabled)
	}
}
