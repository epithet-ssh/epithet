package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
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
			{name: "configured agent", config: "agent:\n  name: work\n  ca-url: https://ca.example\n", profile: "work"},
			{name: "management config override", config: "agent:\n  name: work\n" + command + ":\n  name: personal\n", profile: "personal"},
			{name: "flag override", config: "agent:\n  name: work\n" + command + ":\n  name: personal\n", flags: []string{"--name", "other"}, profile: "other"},
			{name: "explicit default", config: "agent:\n  name: work\n", flags: []string{"--name", "default"}, profile: "default"},
			{name: "socket override", config: "agent:\n  name: invalid/name\n", flags: []string{"--broker", "~/override.sock"}, socket: filepath.Join(home, "override.sock")},
			{name: "configured socket", config: "agent:\n  name: work\n" + command + ":\n  broker: /tmp/configured.sock\n", socket: "/tmp/configured.sock"},
			{name: "invalid inherited profile", config: "agent:\n  name: invalid/name\n", invalid: true},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tc.config), 0600))
				var root struct {
					Config    kong.ConfigFlag `name:"config"`
					Inventory InventoryCLI    `cmd:"inventory"`
					Directory DirectoryCLI    `cmd:"directory"`
				}
				parser, err := kong.New(&root, kong.Configuration(kongyaml.Loader))
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
				socket, err := selected.resolveSocket([]string{string(root.Config)})
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
