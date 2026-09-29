package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
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
