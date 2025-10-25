package broker

import (
	"net/rpc"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestBroker_AgentMapInitialized(t *testing.T) {
	authCommand := "echo '6:thello,'"
	socketPath := t.TempDir() + "/broker.sock"

	b := New(*testLogger(t), socketPath, authCommand)

	// Verify agents map is initialized
	require.NotNil(t, b.agents)
	require.Len(t, b.agents, 0)
}

func TestBroker_NoAgentReturnsNotAllowed(t *testing.T) {
	ctx := t.Context()
	authCommand := "echo '6:thello,'"
	socketPath := "/tmp/test-broker.sock"

	b := New(*testLogger(t), socketPath, authCommand)

	// Serve in background
	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	defer b.Close()

	// Give broker time to start
	time.Sleep(50 * time.Millisecond)

	// Connect via RPC
	client, err := rpc.Dial("unix", socketPath)
	require.NoError(t, err)
	defer client.Close()

	// Make a Match request with no existing agent
	req := MatchRequest{
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
		},
		ConnectionHash: "nonexistent-hash",
	}
	var resp MatchResponse

	err = client.Call("Broker.Match", req, &resp)
	require.NoError(t, err)

	// Should return Allow=false (no agent available)
	require.False(t, resp.Allow)
}
