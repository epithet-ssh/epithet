package broker

import (
	"context"
	"io"
	"testing"

	pb "github.com/epithet-ssh/epithet/pkg/brokerv1"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

func TestBroker_AgentMapInitialized(t *testing.T) {
	t.Parallel()
	authCommand := "echo '6:thello,'"
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, authCommand, testClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)

	// Verify agents map is initialized.
	require.NotNil(t, b.agents)
	require.Len(t, b.agents, 0)
}

func TestBroker_NoAgentReturnsNotAllowed(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	authCommand := "echo '6:thello,'"
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, authCommand, testClient(t, "http://localhost:9999"), agentSocketDir)
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

	// Connect via gRPC.
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewBrokerServiceClient(conn)

	// Make a Match request with no existing agent.
	stream, err := client.Match(context.Background(), &pb.MatchRequest{
		Connection: &pb.Connection{
			RemoteHost: "server.example.com",
			Hash:       "nonexistent-hash",
		},
	})
	require.NoError(t, err)

	// Read the result from stream.
	var result *pb.MatchResult
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if r, ok := event.Event.(*pb.MatchEvent_Result); ok {
			result = r.Result
		}
	}

	require.NotNil(t, result)
	// Should return Allow=false (no agent available).
	require.False(t, result.Allow)
}
