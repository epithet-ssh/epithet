package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	authoidc "github.com/epithet-ssh/epithet/pkg/auth/oidc"
	"github.com/stretchr/testify/require"
)

type testBrokerProcess struct{ ready chan struct{} }

func (b *testBrokerProcess) Ready() <-chan struct{} { return b.ready }
func (b *testBrokerProcess) Serve(ctx context.Context) error {
	close(b.ready)
	<-ctx.Done()
	return ctx.Err()
}

func TestRunAgentCommandReturnsChildStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := runAgentCommand(ctx, cancel, &testBrokerProcess{ready: make(chan struct{})}, []string{"sh", "-c", "exit 7"})
	require.Error(t, err)
	exitErr, ok := err.(interface{ ExitCode() int })
	require.True(t, ok)
	require.Equal(t, 7, exitErr.ExitCode())
}

func TestRunAgentCommandStopsBrokerAfterSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, runAgentCommand(ctx, cancel, &testBrokerProcess{ready: make(chan struct{})}, []string{"sh", "-c", "exit 0"}))
	require.ErrorIs(t, ctx.Err(), context.Canceled)
}

func TestGenerateSSHConfigIsTagGated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-config.conf")
	a := &AgentCLI{Name: "work"}
	require.NoError(t, a.generateSSHConfig(path, "/run/agent", "/run/broker.sock", "/home/u"))

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "Match tagged epithet-work\n    IdentityAgent /run/agent/%C")
	require.Contains(t, s, `Match final tagged epithet-work exec`)
	require.Contains(t, s, "--broker '/run/broker.sock'")
	require.Less(t, strings.Index(s, "Match tagged epithet-work\n"), strings.Index(s, "Match final tagged epithet-work exec"),
		"IdentityAgent selection must precede the final broker invocation")
}

func TestProfileNameValidation(t *testing.T) {
	require.Error(t, validateProfileName("has space"))
	require.Error(t, validateProfileName("has/slash"))
	require.NoError(t, validateProfileName("home-2"))
}

func TestResolveLoginMethod(t *testing.T) {
	tests := []struct {
		name, configured   string
		environment        map[string]string
		want               authoidc.LoginMethod
		wantInferredDevice bool
	}{
		{name: "local auto", configured: "auto", want: authoidc.LoginBrowser},
		{name: "SSH connection", configured: "auto", environment: map[string]string{"SSH_CONNECTION": "client 1 server 2"}, want: authoidc.LoginDevice, wantInferredDevice: true},
		{name: "SSH tty", configured: "auto", environment: map[string]string{"SSH_TTY": "/dev/pts/1"}, want: authoidc.LoginDevice, wantInferredDevice: true},
		{name: "explicit browser overrides SSH", configured: "browser", environment: map[string]string{"SSH_CONNECTION": "set"}, want: authoidc.LoginBrowser},
		{name: "explicit device", configured: "device", want: authoidc.LoginDevice},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(name string) string { return tc.environment[name] }
			got, inferred := resolveLoginMethod(tc.configured, getenv)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.wantInferredDevice, inferred)
		})
	}
}

func TestAgentParsesLoginMethodAndSubprocess(t *testing.T) {
	var command struct {
		Agent AgentCLI `cmd:""`
	}
	parser, err := kong.New(&command)
	require.NoError(t, err)
	_, err = parser.Parse([]string{"agent", "--login-method", "browser", "zsh", "-f"})
	require.NoError(t, err)
	require.Equal(t, "browser", command.Agent.LoginMethod)
	require.Equal(t, []string{"zsh", "-f"}, command.Agent.Start.Command)
}

func TestAgentControlCommandsResolveBrokerFromProfileWithoutCAURL(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	got, err := resolveAgentBrokerSocket(&AgentCLI{Name: "work"}, "")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(homeDir, ".epithet", "run", "work", "broker.sock"), got)
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
	require.Contains(t, string(out), "Match tagged epithet\n")
	require.Contains(t, string(out), "Match final tagged epithet exec")
	require.NotContains(t, string(out), "epithet-default")
}
