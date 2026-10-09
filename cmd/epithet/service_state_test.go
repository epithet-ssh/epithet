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

func TestServiceStatePathsAndModeSelection(t *testing.T) {
	base, err := config.SystemStateDir()
	require.NoError(t, err)
	for _, name := range []string{filepath.Join("directory", "directory.db"), filepath.Join("inventory", "inventory.db")} {
		path, err := serviceStatePath("", name)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(base, name), path)
		path, err = serviceStatePath("custom/state", name)
		require.NoError(t, err)
		require.Equal(t, filepath.Join("custom/state", name), path)
	}
	for _, directoryMode := range []string{"static", "scim"} {
		t.Run(directoryMode, func(t *testing.T) {
			dir := t.TempDir()
			users := filepath.Join(dir, "users.yaml")
			state := filepath.Join(dir, "state")
			require.NoError(t, os.WriteFile(users, []byte("users: []\n"), 0600))
			c := InventoryCLI{Check: true, StateDir: state}
			// Service startup must not consult client profile/socket configuration.
			c.ManagementCLI = ManagementCLI{Name: "invalid/profile", Broker: "/missing/agent.sock"}
			require.NoError(t, c.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{}))
			d := DirectoryCLI{Check: true, Mode: directoryMode, StateDir: state, Static: []string{users}}
			require.NoError(t, (&DirectoryServeCLI{}).Run(&d, slog.New(slog.DiscardHandler), tlsconfig.Config{}))
			require.FileExists(t, filepath.Join(state, "inventory", "inventory.db"))
			if directoryMode == "scim" {
				require.FileExists(t, filepath.Join(state, "directory", "directory.db"))
			} else {
				require.NoDirExists(t, filepath.Join(state, "directory"))
			}
		})
	}
}
