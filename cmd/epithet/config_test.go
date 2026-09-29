package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestFlatConfigUsesFlagNamesAndKongTypes(t *testing.T) {
	root := cli
	resolver, err := loadCLIConfig(strings.NewReader(`
ca = ["https://one.example/", "priority=200:https://two.example/"]
agent-name = "work"
ca-timeout = "30s"
verbose = 2
insecure = false
oidc-issuer = "https://issuer.example/"
certificate-extension = { permit-pty = "", permit-port-forwarding = "" }
after = 9007199254740993
`))
	require.NoError(t, err)
	parse := func(args ...string) {
		t.Helper()
		parser, err := kong.New(&root, kong.Vars{"version": "test"}, kong.Resolvers(resolver))
		require.NoError(t, err)
		_, err = parser.Parse(args)
		require.NoError(t, err)
	}
	parse("agent")
	require.Equal(t, []string{"https://one.example/", "priority=200:https://two.example/"}, root.Agent.CaURL)
	require.Equal(t, "work", root.Agent.Name)
	require.Equal(t, 30*time.Second, root.Agent.CaTimeout)
	require.Equal(t, 2, root.Verbose)
	require.False(t, root.Insecure)
	parse("control", "--directory", "https://directory.example/")
	require.Equal(t, "https://issuer.example/", root.Control.OIDC.Issuer)
	parse("ca", "--directory", "https://directory.example/", "--inventory", "https://inventory.example/")
	require.Equal(t, "https://issuer.example/", root.CA.OIDC.Issuer)
	require.Equal(t, map[string]string{"permit-pty": "", "permit-port-forwarding": ""}, root.CA.Extension)
	parse("directory", "groups", "audit")
	require.EqualValues(t, 9007199254740993, root.Directory.Groups.Audit.After)
}

func TestFlatConfigMultilineInlineTable(t *testing.T) {
	root := cli
	resolver, err := loadCLIConfig(strings.NewReader(`
certificate-extension = {
  permit-pty = "",
  permit-user-rc = "",
  permit-port-forwarding = ""
}
certificate-default-ttl = "5m"
`))
	require.NoError(t, err)
	parser, err := kong.New(&root, kong.Vars{"version": "test"}, kong.Resolvers(resolver))
	require.NoError(t, err)
	_, err = parser.Parse([]string{"ca", "--directory", "https://directory.example/", "--inventory", "https://inventory.example/"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"permit-pty": "", "permit-user-rc": "", "permit-port-forwarding": "",
	}, root.CA.Extension)
	require.Equal(t, "5m", root.CA.DefaultExpiration)
}

func TestFlatConfigPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, config, env string
		args              []string
		want              string
	}{
		{name: "built-in", want: "builtin"},
		{name: "environment", env: "environment", want: "environment"},
		{name: "config over environment", config: `value = "config"`, env: "environment", want: "config"},
		{name: "empty config value", config: `value = ""`, env: "environment", want: ""},
		{name: "CLI over config and environment", config: `value = "config"`, env: "environment", args: []string{"--value", "cli"}, want: "cli"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("EPITHET_TEST_VALUE", tc.env)
			}
			var root struct {
				Value string `default:"builtin" env:"EPITHET_TEST_VALUE"`
			}
			resolver, err := loadCLIConfig(strings.NewReader(tc.config))
			require.NoError(t, err)
			parser, err := kong.New(&root, kong.Resolvers(resolver))
			require.NoError(t, err)
			_, err = parser.Parse(tc.args)
			require.NoError(t, err)
			require.Equal(t, tc.want, root.Value)
		})
	}
}

func TestFlatConfigCollectionsAndFalseReplaceDefaults(t *testing.T) {
	t.Setenv("EPITHET_TEST_ITEMS", "environment")
	t.Setenv("EPITHET_TEST_ENABLED", "true")
	var root struct {
		Items   []string `default:"builtin" env:"EPITHET_TEST_ITEMS"`
		Enabled bool     `default:"true" env:"EPITHET_TEST_ENABLED"`
	}
	resolver, err := loadCLIConfig(strings.NewReader("items = []\nenabled = false\n"))
	require.NoError(t, err)
	parser, err := kong.New(&root, kong.Resolvers(resolver))
	require.NoError(t, err)
	_, err = parser.Parse(nil)
	require.NoError(t, err)
	require.Empty(t, root.Items)
	require.False(t, root.Enabled)
}

func TestFlatConfigRejectsDuplicateKeysAndRequiresArrays(t *testing.T) {
	_, err := loadCLIConfig(strings.NewReader("agent-name = 'one'\nagent-name = 'two'\n"))
	require.Error(t, err)
	resolver, err := loadCLIConfig(strings.NewReader(`ca = "https://ca.example/"`))
	require.NoError(t, err)
	var root struct {
		Agent AgentCLI `cmd:"agent"`
	}
	parser, err := kong.New(&root, kong.Resolvers(resolver))
	require.NoError(t, err)
	_, err = parser.Parse([]string{"agent"})
	require.ErrorContains(t, err, `config key "ca" requires an array`)
}

func TestFlatConfigFileAndCLIListsReplaceEarlierValues(t *testing.T) {
	dir := t.TempDir()
	defaults := filepath.Join(dir, "defaults.toml")
	explicit := filepath.Join(dir, "explicit.toml")
	require.NoError(t, os.WriteFile(defaults, []byte("ca = ['https://default.example/']\nagent-name = 'work'\n"), 0600))
	require.NoError(t, os.WriteFile(explicit, []byte("ca = ['https://explicit.example/']\n"), 0600))
	for _, override := range []bool{false, true} {
		var root struct {
			Config kong.ConfigFlag
			Agent  AgentCLI `cmd:"agent"`
		}
		parser, err := kong.New(&root, kong.Configuration(loadCLIConfig, defaults))
		require.NoError(t, err)
		args := []string{"--config", explicit, "agent"}
		want := []string{"https://explicit.example/"}
		if override {
			args = append(args, "--ca", "https://cli-one.example/", "--ca", "https://cli-two.example/")
			want = []string{"https://cli-one.example/", "https://cli-two.example/"}
		}
		_, err = parser.Parse(args)
		require.NoError(t, err)
		require.Equal(t, want, root.Agent.CaURL)
		require.Equal(t, "work", root.Agent.Name)
	}
}
