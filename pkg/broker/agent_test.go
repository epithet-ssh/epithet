package broker

import (
	"net/rpc"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/stretchr/testify/require"
)

// testClient creates a test CA client for use in tests
func testClient(t *testing.T, url string) *caclient.Client {
	t.Helper()
	endpoints := []caclient.CAEndpoint{{URL: url, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	if err != nil {
		t.Fatalf("failed to create test CA client: %v", err)
	}
	return client
}

func TestBroker_AgentMapInitialized(t *testing.T) {
	t.Parallel()
	authCommand := "echo '6:thello,'"
	// Use short paths to avoid Unix socket path length limits
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, authCommand, testClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)

	// Verify agents map is initialized
	require.NotNil(t, b.agents)
	require.Len(t, b.agents, 0)
}

func TestBroker_NoAgentReturnsNotAllowed(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	authCommand := "echo '6:thello,'"
	// Use short paths to avoid Unix socket path length limits
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, authCommand, testClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)

	// Serve in background
	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	defer b.Close()

	// Wait for broker to be ready
	<-b.Ready()

	// Connect via RPC
	client, err := rpc.Dial("unix", socketPath)
	require.NoError(t, err)
	defer client.Close()

	// Make a Match request with no existing agent
	req := MatchRequest{
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			Hash:       "nonexistent-hash",
		},
	}
	var resp MatchResponse

	err = client.Call("Broker.Match", req, &resp)
	require.NoError(t, err)

	// Should return Allow=false (no agent available)
	require.False(t, resp.Allow)
}
