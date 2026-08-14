package broker

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/stretchr/testify/require"
)

// testClient creates a test CA client for use in tests.
func testClient(t *testing.T, url string) *caclient.Client {
	t.Helper()
	endpoints := []caclient.CAEndpoint{{URL: url, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	if err != nil {
		t.Fatalf("failed to create test CA client: %v", err)
	}
	return client
}

// stubTokenFunc always fails. Used by tests that never reach the auth step,
// or that only need the match path to fail past it (e.g. no CA reachable).
func stubTokenFunc(ctx context.Context, out io.Writer, force bool) (string, error) {
	return "", fmt.Errorf("auth not configured for this test")
}

func TestBroker_AgentMapInitialized(t *testing.T) {
	t.Parallel()
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, stubTokenFunc, testClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)

	// Verify agents map is initialized.
	require.NotNil(t, b.agents)
	require.Len(t, b.agents, 0)
}

func TestBroker_NoAgentReturnsNotAllowed(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, stubTokenFunc, testClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	// Serve in background.
	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	defer b.Close()

	// Wait for broker to be ready.
	<-b.Ready()

	// Make a Match request with no existing agent.
	result := callMatch(t, socketPath, policy.Connection{
		RemoteHost: "server.example.com",
		Hash:       "nonexistent-hash",
	})

	require.NotNil(t, result)
	// Should return Allow=false (no agent available).
	require.False(t, result.Allow)
}
