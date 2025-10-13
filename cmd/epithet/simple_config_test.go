package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadSimpleConfig(t *testing.T) {
	configContent := `# Epithet agent configuration
match skife.org
match *.woob.skife.org
ca-url https://ca.example.com/epithet

# Comments and empty lines are ignored
match another.example.com
`

	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "epithet.conf")
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	cfg, err := LoadSimpleConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Check values
	require.Equal(t, "https://ca.example.com/epithet", cfg.CaURL)
	require.Len(t, cfg.Match, 3)
	require.Contains(t, cfg.Match, "skife.org")
	require.Contains(t, cfg.Match, "*.woob.skife.org")
	require.Contains(t, cfg.Match, "another.example.com")
}

func TestLoadSimpleConfig_DuplicateCAURL(t *testing.T) {
	configContent := `match skife.org
ca-url https://ca1.example.com/
ca-url https://ca2.example.com/
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "epithet.conf")
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	_, err = LoadSimpleConfig(configFile)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca-url can only be specified once")
}

func TestLoadSimpleConfig_UnknownDirective(t *testing.T) {
	configContent := `match skife.org
unknown-directive some-value
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "epithet.conf")
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	_, err = LoadSimpleConfig(configFile)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown directive")
}

func TestLoadSimpleConfig_InvalidFormat(t *testing.T) {
	configContent := `match skife.org
just-a-word
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "epithet.conf")
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	_, err = LoadSimpleConfig(configFile)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid format")
}

func TestMergeWithFlags_Additive(t *testing.T) {
	cfg := &SimpleConfig{
		Match: []string{"config1.org", "config2.org"},
		CaURL: "https://ca.example.com/",
	}

	// Add more match patterns via flags
	cfg.MergeWithFlags([]string{"flag1.org", "flag2.org"}, "")

	require.Len(t, cfg.Match, 4)
	require.Contains(t, cfg.Match, "config1.org")
	require.Contains(t, cfg.Match, "config2.org")
	require.Contains(t, cfg.Match, "flag1.org")
	require.Contains(t, cfg.Match, "flag2.org")
	require.Equal(t, "https://ca.example.com/", cfg.CaURL)
}

func TestMergeWithFlags_CAURLOverride(t *testing.T) {
	cfg := &SimpleConfig{
		Match: []string{"config.org"},
		CaURL: "https://ca-config.example.com/",
	}

	// Override CA URL via flag
	cfg.MergeWithFlags([]string{}, "https://ca-flag.example.com/")

	require.Equal(t, "https://ca-flag.example.com/", cfg.CaURL)
	require.Len(t, cfg.Match, 1)
}

func TestMergeWithFlags_Both(t *testing.T) {
	cfg := &SimpleConfig{
		Match: []string{"config.org"},
		CaURL: "https://ca-config.example.com/",
	}

	// Both: add match patterns and override CA URL
	cfg.MergeWithFlags([]string{"flag.org"}, "https://ca-flag.example.com/")

	require.Len(t, cfg.Match, 2)
	require.Contains(t, cfg.Match, "config.org")
	require.Contains(t, cfg.Match, "flag.org")
	require.Equal(t, "https://ca-flag.example.com/", cfg.CaURL)
}
