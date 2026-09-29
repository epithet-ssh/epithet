package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	authoidc "github.com/epithet-ssh/epithet/pkg/auth/oidc"
	"github.com/epithet-ssh/epithet/pkg/broker"
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

func TestAgentSessionCommands(t *testing.T) {
	for _, tc := range []struct {
		name, output, errorText string
		logout                  bool
		event                   broker.Event
	}{
		{name: "login", event: broker.Event{Identity: &broker.IdentityResponse{Identity: &broker.Identity{Subject: "alice"}}}, output: "Logged in.\n"},
		{name: "login-failed", event: broker.Event{Identity: &broker.IdentityResponse{Error: "login denied"}}, errorText: "login denied"},
		{name: "login-empty", event: broker.Event{Identity: &broker.IdentityResponse{}}, errorText: "no identity"},
		{name: "logout", logout: true, event: broker.Event{Logout: &broker.LogoutResponse{AgentsCleared: 2}}, output: "Logged out; cleared 2 certificate agents.\n"},
		{name: "logout-failed", logout: true, event: broker.Event{Logout: &broker.LogoutResponse{Error: "broker is closed"}}, errorText: "broker is closed"},
		{name: "old-broker", logout: true, event: broker.Event{Result: &broker.MatchResponse{Error: "unknown request"}}, errorText: "restart the agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "epithet-session-")
			require.NoError(t, err)
			t.Cleanup(func() { os.RemoveAll(dir) })
			socket := filepath.Join(dir, "b.sock")
			listener, err := net.Listen("unix", socket)
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				var req broker.Request
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				if req.Match != nil || req.Inventory != nil || (tc.logout && req.Logout == nil) || (!tc.logout && req.Identity == nil) {
					t.Error("expected authentication-only or logout request")
					return
				}
				enc := json.NewEncoder(conn)
				if !tc.logout {
					_ = enc.Encode(broker.Event{Output: "visit login URL\n"})
				}
				_ = enc.Encode(tc.event)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var out, progress bytes.Buffer
			if tc.logout {
				err = (&AgentLogoutCLI{}).run(ctx, socket, &out)
			} else {
				err = (&AgentLoginCLI{}).run(ctx, socket, &out, &progress)
				require.Equal(t, "visit login URL\n", progress.String())
			}
			<-done
			if tc.errorText != "" {
				require.ErrorContains(t, err, tc.errorText)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.output, out.String())
		})
	}
}

func TestAgentSessionUsesProfileAndSocketOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("agent-name = \"work\"\nca = [\"https://ca.example\"]\n"), 0600))
	for _, command := range []string{"identity", "login", "logout"} {
		for _, args := range [][]string{{"agent", command}, {"agent", "--agent-name", "personal", command, "--broker-socket", "/tmp/identity.sock"}} {
			var root struct {
				Agent AgentCLI `cmd:"agent"`
			}
			parser, err := kong.New(&root, kong.Configuration(loadCLIConfig, path))
			require.NoError(t, err)
			_, err = parser.Parse(args)
			require.NoError(t, err)
			override := root.Agent.Identity.Broker
			if command == "login" {
				override = root.Agent.Login.Broker
			}
			if command == "logout" {
				override = root.Agent.Logout.Broker
			}
			socket, err := resolveAgentBrokerSocket(&root.Agent, override)
			require.NoError(t, err)
			if len(args) == 2 {
				home, err := os.UserHomeDir()
				require.NoError(t, err)
				require.Equal(t, filepath.Join(home, ".epithet/run/work/broker.sock"), socket)
			} else {
				require.Equal(t, "/tmp/identity.sock", socket)
			}
		}
	}
}
