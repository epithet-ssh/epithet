package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestStaticDirectoryRecoveryIgnoresDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static.yaml")
	require.NoError(t, os.WriteFile(path, []byte("users:\n - id: admin-sub\n   userName: admin\nhosts:\n - names: [host]\n"), 0600))
	c := DirectoryCLI{Check: true, Mode: "static", StateDir: "/unavailable/state", Static: []string{path}}
	require.NoError(t, (&DirectoryServeCLI{}).Run(&c, slog.New(slog.DiscardHandler), tlsconfig.Config{}))
}

func TestControlTokenConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, literal, file, wantError string }{
		{name: "literal", literal: "secret"}, {name: "file", file: "secret\n"},
		{name: "disabled"}, {name: "both", literal: "secret", file: "secret", wantError: "use either"},
		{name: "empty file", file: "\n", wantError: "nonempty bearer token"},
		{name: "invalid", literal: "not a token", wantError: "without whitespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ControlCLI{SCIMToken: tc.literal}
			if tc.file != "" {
				c.SCIMTokenFile = filepath.Join(t.TempDir(), "token")
				require.NoError(t, os.WriteFile(c.SCIMTokenFile, []byte(tc.file), 0600))
			}
			token, err := c.provisioningToken()
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
				if tc.name != "disabled" {
					require.Equal(t, "secret", token)
				}
			}
		})
	}
}

func TestServiceStatePathsAndModeSelection(t *testing.T) {
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
	for _, directoryMode := range []string{"static", "scim"} {
		for _, mode := range []string{"", "static", "enrollment"} {
			t.Run(directoryMode+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				hosts := filepath.Join(dir, "hosts.yaml")
				state := filepath.Join(dir, "state")
				require.NoError(t, os.WriteFile(hosts, []byte("hosts: []\n"), 0600))
				c := InventoryCLI{Check: true, Static: []string{hosts}, StateDir: state, InventoryMode: mode}
				// Service startup must not consult client profile/socket configuration.
				c.ManagementCLI = ManagementCLI{Name: "invalid/profile", Broker: "/missing/agent.sock"}
				require.NoError(t, c.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{}))
				d := DirectoryCLI{Check: true, Mode: directoryMode, StateDir: state, Static: []string{hosts}}
				require.NoError(t, (&DirectoryServeCLI{}).Run(&d, slog.New(slog.DiscardHandler), tlsconfig.Config{}))
				if mode != "static" {
					require.DirExists(t, filepath.Join(state, "inventory", "records"))
				} else {
					require.NoDirExists(t, filepath.Join(state, "inventory"))
				}
				if directoryMode == "scim" {
					require.FileExists(t, filepath.Join(state, "directory", "directory.db"))
				} else {
					require.NoDirExists(t, filepath.Join(state, "directory"))
					if mode == "static" {
						require.NoDirExists(t, state)
					}
				}
			})
		}
	}
}

func TestInventoryPrincipalModeDefaultAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, configMode, hostFields string
		wantError                    bool
	}{
		{name: "default requires a domain", wantError: true},
		{name: "default accepts a domain", hostFields: "    domain: fleet\n"},
		{name: "explicit account-name default", configMode: "account-name"},
		{name: "per-host account-name override", hostFields: "    principal-mode: account-name\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "static.yaml")
			require.NoError(t, os.WriteFile(path, []byte("domains: [fleet]\nhosts:\n  - names: [host.example]\n"+tc.hostFields), 0600))
			c := InventoryCLI{Check: true, InventoryMode: "static", PrincipalMode: tc.configMode, Static: []string{path}}
			err := c.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{})
			if tc.wantError {
				require.ErrorContains(t, err, "uses epithet-principal-v1 but has no domain")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
