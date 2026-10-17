package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestServiceStatePathsAndModeSelection(t *testing.T) {
	base, err := systemStateDir(runtime.GOOS, os.Getenv)
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

func TestDefaultPath(t *testing.T) {
	tests := map[string]string{
		"linux":     "/var/lib/epithet/realm",
		"freebsd":   "/var/db/epithet/realm",
		"openbsd":   "/var/db/epithet/realm",
		"netbsd":    "/var/db/epithet/realm",
		"dragonfly": "/var/db/epithet/realm",
		"solaris":   "/var/opt/epithet/realm",
		"illumos":   "/var/opt/epithet/realm",
		"aix":       "/var/opt/epithet/realm",
		"darwin":    "/Library/Application Support/Epithet/realm",
	}
	for goos, want := range tests {
		t.Run(goos, func(t *testing.T) {
			got, err := defaultRealmPath(goos, func(string) string { return "" })
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestDefaultPathWindowsUsesProgramData(t *testing.T) {
	got, err := defaultRealmPath("windows", func(name string) string {
		require.Equal(t, "ProgramData", name)
		return `C:\ProgramData`
	})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(`C:\ProgramData`, "realm"), got)
}

func TestDefaultPathRejectsUnknownOS(t *testing.T) {
	_, err := defaultRealmPath("plan9", func(string) string { return "" })
	require.ErrorContains(t, err, "use an explicit path")
}

func TestDefaultPathMatchesCurrentOS(t *testing.T) {
	if runtime.GOOS == "plan9" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("current OS deliberately has no host-enrollment default")
	}
	_, err := defaultRealmPath(runtime.GOOS, os.Getenv)
	require.NoError(t, err)
}
