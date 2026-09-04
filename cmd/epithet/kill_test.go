package main

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestRequestAgentKillUsesTypedProtocol(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	received := make(chan broker.Request, 1)
	go func() {
		var request broker.Request
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			return
		}
		received <- request
		_ = json.NewEncoder(server).Encode(broker.Event{Kill: &broker.KillResponse{
			ID: "agent-id",
			Connection: policy.Connection{
				RemoteHost: "host.example.com",
				RemoteUser: "root",
				Port:       22,
				Hash:       "agent-id",
			},
		}})
	}()

	response, err := requestAgentKill(client, "agent-id")
	require.NoError(t, err)
	require.Equal(t, policy.ConnectionHash("agent-id"), response.ID)
	request := <-received
	require.NotNil(t, request.Kill)
	require.Equal(t, policy.ConnectionHash("agent-id"), request.Kill.ID)
}

func TestRequestAgentKillSurfacesTypedError(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	go func() {
		var request broker.Request
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			return
		}
		_ = json.NewEncoder(server).Encode(broker.Event{Kill: &broker.KillResponse{
			ID:    request.Kill.ID,
			Error: `agent "missing" does not exist`,
		}})
	}()

	_, err := requestAgentKill(client, "missing")
	require.EqualError(t, err, `broker refused to kill agent: agent "missing" does not exist`)
}

func TestWriteAgentKillNamesConnection(t *testing.T) {
	var output bytes.Buffer
	writeAgentKill(&output, &broker.KillResponse{
		ID: "agent-id",
		Connection: policy.Connection{
			RemoteHost: "host.example.com",
			RemoteUser: "root",
			Port:       2222,
		},
	})
	require.Equal(t, "Killed agent agent-id (root@host.example.com:2222)\n", output.String())
}
