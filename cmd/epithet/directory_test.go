package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/stretchr/testify/require"
)

func TestDirectoryUsersListOutput(t *testing.T) {
	snapshot := &inventoryapi.UserSnapshot{Revision: "directory:7", Users: []inventoryapi.DirectoryUser{
		{UserName: "alice", ID: "provider-id", Active: true, Groups: []string{"ops", "wheel"}, Department: "engineering"},
		{UserName: "disabled\nuser", ID: "id\t2", Active: false, Groups: []string{"odd\x1bgroup"}},
	}}
	var output bytes.Buffer
	require.NoError(t, (&DirectoryUsersListCLI{}).writeOutput(&output, snapshot))
	require.Equal(t, "USERNAME\tID\tACTIVE\tGROUPS\nalice\tprovider-id\ttrue\tops,wheel\n\"disabled\\nuser\"\t\"id\\t2\"\tfalse\t\"odd\\x1bgroup\"\n", output.String())
	output.Reset()
	require.NoError(t, (&DirectoryUsersListCLI{JSON: true}).writeOutput(&output, snapshot))
	var decoded inventoryapi.UserSnapshot
	require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
	require.Equal(t, *snapshot, decoded)
	output.Reset()
	require.NoError(t, (&DirectoryUsersListCLI{JSON: true}).writeOutput(&output, &inventoryapi.UserSnapshot{Revision: "empty", Users: []inventoryapi.DirectoryUser{}}))
	require.JSONEq(t, `{"revision":"empty","users":[]}`, output.String())
}

func TestDirectoryUsersCommand(t *testing.T) {
	var root struct {
		Directory DirectoryCLI `cmd:"directory"`
	}
	parser, err := kong.New(&root)
	require.NoError(t, err)
	_, err = parser.Parse([]string{"directory", "users", "list", "--json", "--name", "work"})
	require.NoError(t, err)
	require.True(t, root.Directory.Users.List.JSON)
	require.Equal(t, "work", root.Directory.Name)
}
