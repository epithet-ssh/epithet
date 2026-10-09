package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestInventoryCheckValidatesConfiguredManagedDatabase(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	path := filepath.Join(state, "inventory", "inventory.db")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte("not a database"), 0600))
	command := InventoryCLI{Check: true, StateDir: state}
	err := command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{})
	require.ErrorContains(t, err, "opening managed inventory")
	require.NoError(t, os.Remove(path))
	require.NoError(t, command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{}))
}

func TestInventoryCheckCreatesManagedDatabase(t *testing.T) {
	state := t.TempDir()
	command := InventoryCLI{Check: true, StateDir: state}
	require.NoError(t, command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{}))
	require.FileExists(t, filepath.Join(state, "inventory", "inventory.db"))
}
