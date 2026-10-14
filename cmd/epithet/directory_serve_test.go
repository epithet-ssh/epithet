package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestStaticDirectoryRecoveryIgnoresDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static.yaml")
	require.NoError(t, os.WriteFile(path, []byte("users:\n - id: admin-sub\n   userName: admin\nhosts:\n - names: [host]\n"), 0600))
	c := DirectoryCLI{Check: true, Mode: "static", StateDir: "/unavailable/state", Static: []string{path}}
	require.NoError(t, (&DirectoryServeCLI{}).Run(&c, slog.New(slog.DiscardHandler), tlsconfig.Config{}))
}

func TestDirectoryIdentityAttributeConfiguration(t *testing.T) {
	resolver, err := loadCLIConfig(strings.NewReader(`scim-user-id-attribute = "userName"`))
	require.NoError(t, err)
	var root struct {
		Directory DirectoryCLI `cmd:"directory"`
	}
	parser, err := kong.New(&root, kong.Resolvers(resolver))
	require.NoError(t, err)
	_, err = parser.Parse([]string{"directory", "--directory-mode", "scim", "--state-dir", t.TempDir(), "--check"})
	require.NoError(t, err)
	require.Equal(t, "userName", root.Directory.SCIMUserIDAttribute)
	require.NoError(t, root.Directory.Serve.Run(&root.Directory, slog.New(slog.DiscardHandler), tlsconfig.Config{}))
	root.Directory.SCIMUserIDAttribute = "unknown"
	require.ErrorContains(t, root.Directory.Serve.Run(&root.Directory, slog.New(slog.DiscardHandler), tlsconfig.Config{}), "unsupported SCIM user ID attribute")
}
