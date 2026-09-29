package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestInventoryCheckValidatesConfiguredManagedFiles(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	records := filepath.Join(state, "inventory", "records")
	require.NoError(t, os.MkdirAll(records, 0700))
	item := filepath.Join(records, strings.Repeat("a", 64)+".yaml")
	require.NoError(t, os.WriteFile(item, []byte("version: 99\n"), 0600))
	command := InventoryCLI{Check: true, StateDir: state, InventoryMode: "enrollment"}
	err := command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{})
	require.ErrorContains(t, err, "unsupported item version")
	require.NoError(t, os.Remove(item))
	require.NoError(t, command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{}))
}

func TestInventoryStaticFilesOptionalOnlyInEnrollmentMode(t *testing.T) {
	for _, tc := range []struct {
		name, mode, pattern string
		wantError           bool
	}{
		{name: "enrollment without static", mode: "enrollment"},
		{name: "default without static"},
		{name: "static requires files", mode: "static", wantError: true},
		{name: "enrollment missing file", mode: "enrollment", pattern: "missing.yaml", wantError: true},
		{name: "enrollment unmatched glob", mode: "enrollment", pattern: "*.yaml", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			command := InventoryCLI{Check: true, StateDir: state, InventoryMode: tc.mode}
			if tc.pattern != "" {
				command.Static = []string{filepath.Join(state, tc.pattern)}
			}
			err := command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{})
			if tc.wantError {
				require.ErrorContains(t, err, "no inventory files match")
				require.NoDirExists(t, filepath.Join(state, "inventory"))
			} else {
				require.NoError(t, err)
				require.DirExists(t, filepath.Join(state, "inventory", "records"))
			}
		})
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
