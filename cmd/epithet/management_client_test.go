package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestManagementAgentProfileConfiguration(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	for _, command := range []string{"inventory", "directory"} {
		for _, tc := range []struct {
			name, config    string
			flags           []string
			profile, socket string
			invalid         bool
		}{
			{name: "default", profile: "default"},
			{name: "configured agent", config: `agent-name = "work"`, profile: "work"},
			{name: "flag override", config: `agent-name = "personal"`, flags: []string{"--agent-name", "other"}, profile: "other"},
			{name: "explicit default", config: `agent-name = "work"`, flags: []string{"--agent-name", "default"}, profile: "default"},
			{name: "socket override", config: `agent-name = "invalid/name"`, flags: []string{"--broker-socket", "~/override.sock"}, socket: filepath.Join(home, "override.sock")},
			{name: "configured socket", config: `agent-name = "work"
broker-socket = "/tmp/configured.sock"`, socket: "/tmp/configured.sock"},
			{name: "invalid profile", config: `agent-name = "invalid/name"`, invalid: true},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.toml")
				require.NoError(t, os.WriteFile(path, []byte(tc.config), 0600))
				var root struct {
					Config    kong.ConfigFlag `name:"config"`
					Inventory InventoryCLI    `cmd:"inventory"`
					Directory DirectoryCLI    `cmd:"directory"`
				}
				parser, err := kong.New(&root, kong.Configuration(loadCLIConfig))
				require.NoError(t, err)
				args := []string{"--config", path, command}
				if command == "directory" {
					args = append(args, "groups")
				}
				args = append(args, "list")
				args = append(args, tc.flags...)
				_, err = parser.Parse(args)
				require.NoError(t, err)
				selected := &root.Inventory.ManagementCLI
				if command == "directory" {
					selected = &root.Directory.ManagementCLI
				}
				socket, err := resolveAgentBrokerSocket(&AgentCLI{Name: selected.Name}, selected.Broker)
				if tc.invalid {
					require.ErrorContains(t, err, "invalid profile name")
					return
				}
				require.NoError(t, err)
				want := tc.socket
				if want == "" {
					want = filepath.Join(home, ".epithet", "run", tc.profile, "broker.sock")
				}
				require.Equal(t, want, socket)
			})
		}
	}
}

func TestDirectoryAuditPaginationFlags(t *testing.T) {
	var root struct {
		Directory DirectoryCLI `cmd:"directory"`
	}
	parser, err := kong.New(&root)
	require.NoError(t, err)
	_, err = parser.Parse([]string{"directory", "groups", "audit", "--after", "9007199254740993", "--limit", "25"})
	require.NoError(t, err)
	require.EqualValues(t, 9007199254740993, root.Directory.Groups.Audit.After)
	require.Equal(t, 25, root.Directory.Groups.Audit.Limit)
}
