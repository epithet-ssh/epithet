package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestInventoryDisplayPreservesRevisionAndSource(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer output.Close()
	original := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = original }()
	record := inventoryapi.HostRecord{
		ID:         strings.Repeat("a", 64),
		Revision:   9007199254740993,
		Source:     "dynamic",
		SourceFile: "/inventory/records/item.yaml",
		Proposal:   inventoryapi.Proposal{Names: []string{"host"}, PrincipalMode: "account-name"},
	}
	require.NoError(t, printInventory(record))
	_, err = output.Seek(0, 0)
	require.NoError(t, err)
	data, err := io.ReadAll(output)
	require.NoError(t, err)
	var fields map[string]yaml.Node
	require.NoError(t, yaml.Unmarshal(data, &fields))
	var revision uint64
	revisionNode := fields["revision"]
	require.NoError(t, revisionNode.Decode(&revision))
	require.Equal(t, record.Revision, revision)
	require.Equal(t, record.SourceFile, fields["source-file"].Value)
	require.Equal(t, "dynamic", fields["source"].Value)
	var host inventory.Proposal
	hostNode := fields["host"]
	require.NoError(t, hostNode.Decode(&host))
	require.Nil(t, host.Accounts)
}

func TestInventoryCheckValidatesConfiguredManagedFiles(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	records := filepath.Join(state, "inventory", "records")
	require.NoError(t, os.MkdirAll(records, 0700))
	item := filepath.Join(records, strings.Repeat("a", 64)+".yaml")
	require.NoError(t, os.WriteFile(item, []byte("version: 99\n"), 0600))
	command := InventoryCLI{Check: true, StateDir: state, InventorySource: "managed"}
	err := command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{})
	require.ErrorContains(t, err, "unsupported item version")
	require.NoError(t, os.Remove(item))
	require.NoError(t, command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{}))
}

func TestInventoryStaticFilesOptionalOnlyInManagedMode(t *testing.T) {
	for _, tc := range []struct {
		name, source, pattern string
		wantError             bool
	}{
		{name: "managed without static", source: "managed"},
		{name: "default without static"},
		{name: "static requires files", source: "static", wantError: true},
		{name: "managed missing file", source: "managed", pattern: "missing.yaml", wantError: true},
		{name: "managed unmatched glob", source: "managed", pattern: "*.yaml", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			command := InventoryCLI{Check: true, StateDir: state, InventorySource: tc.source}
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
