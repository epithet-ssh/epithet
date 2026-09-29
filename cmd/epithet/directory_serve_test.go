package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestStaticDirectoryRecoveryIgnoresDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static.yaml")
	require.NoError(t, os.WriteFile(path, []byte("users:\n - id: admin-sub\n   userName: admin\nhosts:\n - names: [host]\n"), 0600))
	c := DirectoryCLI{Check: true, Mode: "static", StateDir: "/unavailable/state", Static: []string{path}}
	require.NoError(t, (&DirectoryServeCLI{}).Run(&c, slog.New(slog.DiscardHandler), tlsconfig.Config{}))
}
