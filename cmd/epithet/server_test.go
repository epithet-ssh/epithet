package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"github.com/epithet-ssh/epithet/pkg/policyserver/inventory"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestServerPrincipalModePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		args   []string
		want   inventory.PrincipalMode
	}{
		{
			name:   "unspecified retains policy default",
			config: "{}\n",
			want:   inventory.AccountNamePrincipals,
		},
		{
			name:   "inherits hashed policy configuration",
			config: "policy:\n  principal-mode: epithet-principal-v1\n",
			want:   inventory.EpithetPrincipalV1,
		},
		{
			name:   "explicit server compatibility overrides hashed policy",
			config: "server:\n  principal-mode: account-name\npolicy:\n  principal-mode: epithet-principal-v1\n",
			want:   inventory.AccountNamePrincipals,
		},
		{
			name:   "explicit server hashed overrides compatibility policy",
			config: "server:\n  principal-mode: epithet-principal-v1\npolicy:\n  principal-mode: account-name\n",
			want:   inventory.EpithetPrincipalV1,
		},
		{
			name:   "CLI compatibility overrides server and policy configuration",
			config: "server:\n  principal-mode: epithet-principal-v1\npolicy:\n  principal-mode: epithet-principal-v1\n",
			args:   []string{"--principal-mode", "account-name"},
			want:   inventory.AccountNamePrincipals,
		},
		{
			name:   "CLI hashed overrides server and policy configuration",
			config: "server:\n  principal-mode: account-name\npolicy:\n  principal-mode: account-name\n",
			args:   []string{"--principal-mode", "epithet-principal-v1"},
			want:   inventory.EpithetPrincipalV1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tc.config), 0o600))
			parse := func(args []string) (*ServerCLI, *PolicyServerCLI) {
				t.Helper()
				var root struct {
					Config kong.ConfigFlag `name:"config"`
					Server ServerCLI       `cmd:"server"`
					Policy PolicyServerCLI `cmd:"policy"`
				}
				parser, err := kong.New(&root, kong.Configuration(kongyaml.Loader))
				require.NoError(t, err)
				_, err = parser.Parse(args)
				require.NoError(t, err)
				return &root.Server, &root.Policy
			}

			server, _ := parse(append([]string{"--config", path, "server"}, tc.args...))
			// Reparse the actual subprocess arguments with the same config, as
			// the combined server does, without starting CA or OIDC services.
			_, policy := parse(server.policyArgs([]string{"--config", path}, "/tmp/policy.sock", "unused-key"))
			require.Equal(t, string(tc.want), policy.PrincipalMode)
		})
	}
}

func TestServerRejectsUnknownPrincipalModeBeforeStartingServices(t *testing.T) {
	server := &ServerCLI{PrincipalMode: "mystery"}
	err := server.Run(nil, tlsconfig.Config{})
	require.ErrorContains(t, err, `unknown principal mode "mystery"`)
}
