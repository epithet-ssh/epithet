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

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/stretchr/testify/require"
)

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
