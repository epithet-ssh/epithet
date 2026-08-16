package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateSSHConfigIsTagGated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-config.conf")
	a := &AgentCLI{Name: "work"}
	require.NoError(t, a.generateSSHConfig(path, "/run/agent", "/run/broker.sock", "/home/u"))

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, `Match tagged epithet-work exec`)
	require.Contains(t, s, "IdentityAgent /run/agent/%C")
	require.Contains(t, s, "--broker '/run/broker.sock'")
	require.NotContains(t, strings.Split(s, "Match tagged")[0], "\nMatch ",
		"nothing before the tagged Match may open a match block")
}

func TestProfileNameValidation(t *testing.T) {
	require.Error(t, validateProfileName("has space"))
	require.Error(t, validateProfileName("has/slash"))
	require.NoError(t, validateProfileName("home-2"))
}

// TestAcquireProfileLockPreventsConcurrentAgents exercises the flock guard
// the same way AgentStartCLI.Run does: acquire once (as the first agent
// process would), then attempt a second acquisition against the same rundir
// (as a concurrent second process for the same --name would) and confirm it
// fails with a clear, actionable error instead of silently succeeding and
// stealing the socket out from under the first process.
func TestAcquireProfileLockPreventsConcurrentAgents(t *testing.T) {
	dir := t.TempDir()

	f1, err := acquireProfileLock(dir, "work")
	require.NoError(t, err)
	t.Cleanup(func() { f1.Close() })

	_, err = acquireProfileLock(dir, "work")
	require.Error(t, err)
	require.EqualError(t, err, `profile "work" is already running (use --name to run a second profile)`)
}

func TestCheckSSHConfigIncludeOrdering(t *testing.T) {
	homeDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(homeDir, ".ssh"), 0700))
	sshConfigPath := filepath.Join(homeDir, ".ssh", "config")
	includePattern := filepath.Join(homeDir, ".epithet", "run", "*", "ssh-config.conf")

	writeConfigAndCheck := func(t *testing.T, content string) string {
		t.Helper()
		require.NoError(t, os.WriteFile(sshConfigPath, []byte(content), 0600))
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		err := checkSSHConfigInclude(homeDir, includePattern, "work", logger)
		require.NoError(t, err)
		return buf.String()
	}

	t.Run("include before tag warns", func(t *testing.T) {
		out := writeConfigAndCheck(t, fmt.Sprintf(
			"Include %s\nHost *.example.com\n    Tag epithet-work\n", includePattern))
		require.Contains(t, out, "Include must come after Tag lines or epithet will never activate")
	})

	t.Run("include after tag: no warning", func(t *testing.T) {
		out := writeConfigAndCheck(t, fmt.Sprintf(
			"Host *.example.com\n    Tag epithet-work\nInclude %s\n", includePattern))
		require.NotContains(t, out, "Include must come after Tag lines")
		require.NotContains(t, out, "no 'Tag epithet-work' lines found")
	})

	t.Run("include with no tags warns", func(t *testing.T) {
		out := writeConfigAndCheck(t, fmt.Sprintf(
			"Host *.example.com\nInclude %s\n", includePattern))
		require.Contains(t, out, "no 'Tag epithet-work' lines found in ~/.ssh/config — epithet will never activate; tag the Host blocks it should handle")
	})
}

func TestProfileTagDefaultIsBareEpithet(t *testing.T) {
	// The default profile drops the "-default" suffix for ergonomics; Match
	// tagged is exact-match, so the bare tag cannot collide with named ones.
	require.Equal(t, "epithet", profileTag("default"))
	require.Equal(t, "epithet-work", profileTag("work"))
}

func TestGenerateSSHConfigDefaultProfileUsesBareTag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-config.conf")
	a := &AgentCLI{Name: "default"}
	require.NoError(t, a.generateSSHConfig(path, "/run/agent", "/run/broker.sock", "/home/u"))

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(out), "Match tagged epithet exec")
	require.NotContains(t, string(out), "epithet-default")
}
