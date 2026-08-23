package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestWriteInspectShowsAgentConnection(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	resp := &broker.InspectResponse{
		SocketPath:     "/run/epithet/broker.sock",
		AgentSocketDir: "/run/epithet/agent",
		Agents: []broker.AgentInfo{{
			Hash: "connection-hash",
			Connection: policy.Connection{
				RemoteHost: "server.example.com",
				RemoteUser: "deploy",
				Port:       2222,
				ProxyJump:  "bastion.example.com",
				Hash:       "connection-hash",
			},
			SocketPath: "/run/epithet/agent/connection-hash",
			ExpiresAt:  now.Add(2 * time.Minute),
		}},
	}

	var out bytes.Buffer
	writeInspect(&out, resp, now)

	require.Contains(t, out.String(), "    Host: server.example.com\n")
	require.Contains(t, out.String(), "    User: deploy\n")
	require.Contains(t, out.String(), "    Port: 2222\n")
	require.Contains(t, out.String(), "    ProxyJump: bastion.example.com\n")
}
