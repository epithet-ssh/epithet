package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestRequestAgentKillUsesTypedProtocol(t *testing.T) {
	received := make(chan broker.Request, 1)
	client := fakeBrokerClient(t, func(server net.Conn) {
		var request broker.Request
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			return
		}
		received <- request
		_ = json.NewEncoder(server).Encode(broker.Event{Kill: &broker.KillResponse{
			ID: "agent-id",
			Connection: wire.Connection{
				RemoteHost: "host.example.com",
				RemoteUser: "root",
				Port:       22,
				Hash:       "agent-id",
			},
		}})
	})

	response, err := client.kill(context.Background(), "agent-id")
	require.NoError(t, err)
	require.Equal(t, wire.ConnectionHash("agent-id"), response.ID)
	request := <-received
	require.NotNil(t, request.Kill)
	require.Equal(t, wire.ConnectionHash("agent-id"), request.Kill.ID)
}

func TestRequestAgentKillSurfacesTypedError(t *testing.T) {
	client := fakeBrokerClient(t, func(server net.Conn) {
		var request broker.Request
		if err := json.NewDecoder(server).Decode(&request); err != nil {
			return
		}
		_ = json.NewEncoder(server).Encode(broker.Event{Kill: &broker.KillResponse{
			ID:    request.Kill.ID,
			Error: `agent "missing" does not exist`,
		}})
	})

	_, err := client.kill(context.Background(), "missing")
	require.EqualError(t, err, `broker refused to kill agent: agent "missing" does not exist`)
}

func TestWriteAgentKillNamesConnection(t *testing.T) {
	var output bytes.Buffer
	writeAgentKill(&output, &broker.KillResponse{
		ID: "agent-id",
		Connection: wire.Connection{
			RemoteHost: "host.example.com",
			RemoteUser: "root",
			Port:       2222,
		},
	})
	require.Equal(t, "Killed agent agent-id (root@host.example.com:2222)\n", output.String())
}
