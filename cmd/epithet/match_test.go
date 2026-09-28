package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestMatchInputsAreCLIOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(`verbose = 2
log-file = "/tmp/match-debug.log"
host = "config-host"
port = "not-a-port"
user = "config-user"
hash = "config-hash"
jump = "config-jump"
broker-socket = "/config/agent.sock"
`), 0600))
	inputs := []string{"--host", "cli-host", "--port", "2222", "--user", "cli-user", "--hash", "cli-hash", "--broker-socket", "/cli/broker.sock"}
	for _, explicitConfig := range []bool{false, true} {
		name := "default config"
		if explicitConfig {
			name = "explicit config"
		}
		t.Run(name, func(t *testing.T) {
			root := cli
			paths := []string{path}
			var prefix []string
			if explicitConfig {
				paths = nil
				prefix = []string{"--config", path}
			}
			parse := func(args ...string) error {
				parser, err := kong.New(&root, kong.Vars{"version": "test"}, kong.Configuration(loadCLIConfig, paths...))
				require.NoError(t, err)
				for _, command := range parser.Model.Children {
					if command.Name == "match" {
						for _, flag := range command.Flags {
							require.Empty(t, flag.Tag.Envs, "%s must remain CLI-only", flag.Name)
						}
					}
				}
				_, err = parser.Parse(append(append([]string{}, prefix...), args...))
				return err
			}

			// Missing CLI inputs remain missing even when configured, and invalid
			// config values must not reach the flag's type decoder.
			for i := 0; i < len(inputs); i += 2 {
				args := append([]string{"match"}, inputs[:i]...)
				args = append(args, inputs[i+2:]...)
				err := parse(args...)
				require.ErrorContains(t, err, "missing flags")
				require.ErrorContains(t, err, inputs[i])
			}
			require.NoError(t, parse(append([]string{"match"}, inputs...)...))
			require.Equal(t, MatchCLI{Host: "cli-host", Port: 2222, User: "cli-user", Hash: "cli-hash", Broker: "/cli/broker.sock"}, root.Match)
			require.Equal(t, 2, root.Verbose)
			require.Equal(t, "/tmp/match-debug.log", root.LogFile)

			args := append(append([]string{"match"}, inputs...), "--jump", "cli-jump")
			require.NoError(t, parse(args...))
			require.Equal(t, "cli-jump", root.Match.Jump)

			// The same flag name on a user-facing command remains configurable.
			require.NoError(t, parse("agent", "inspect"))
			require.Equal(t, "/config/agent.sock", root.Agent.Inspect.Broker)
		})
	}
}
