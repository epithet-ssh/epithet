package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventory"
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
	record := inventory.HostRecord{
		ID:         strings.Repeat("a", 64),
		Revision:   9007199254740993,
		Source:     "dynamic",
		SourceFile: "/inventory/records/item.yaml",
		Proposal:   inventory.Proposal{Names: []string{"host"}, PrincipalMode: inventory.AccountNamePrincipals},
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
	static := filepath.Join(dir, "static.yaml")
	require.NoError(t, os.WriteFile(static, []byte("users: []\n"), 0600))
	state := filepath.Join(dir, "state")
	records := filepath.Join(state, "inventory", "records")
	require.NoError(t, os.MkdirAll(records, 0700))
	item := filepath.Join(records, strings.Repeat("a", 64)+".yaml")
	require.NoError(t, os.WriteFile(item, []byte("version: 99\n"), 0600))
	command := InventoryCLI{Check: true, Static: []string{static}, StateDir: state, InventorySource: "managed",
		OIDC: InventoryOIDCConfig{Issuer: "https://issuer.example"}}
	err := command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{})
	require.ErrorContains(t, err, "unsupported item version")
	require.NoError(t, os.Remove(item))
	require.NoError(t, command.runServer(slog.New(slog.DiscardHandler), tlsconfig.Config{}))
}
