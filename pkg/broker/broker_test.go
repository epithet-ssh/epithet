package broker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	pb "github.com/epithet-ssh/epithet/pkg/brokerv1"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// testCAClient creates a test CA client for use in tests.
func testCAClient(t *testing.T, url string) *caclient.Client {
	t.Helper()
	endpoints := []caclient.CAEndpoint{{URL: url, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	if err != nil {
		t.Fatalf("failed to create test CA client: %v", err)
	}
	return client
}

// testCAClientOK creates a CA client backed by a server that accepts any
// request with a bare 200 OK and no body. Used by tests that only need the
// match flow to reach the CA (past auth), not to receive a real certificate.
func testCAClientOK(t *testing.T) *caclient.Client {
	t.Helper()

	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(caServer.Close)

	return testCAClient(t, caServer.URL)
}

// testTokenFunc returns a TokenFunc that mints a fresh, valid JWT from idp on
// every call, with no user-visible output.
func testTokenFunc(t *testing.T, idp *oidctest.IdP) TokenFunc {
	t.Helper()
	return func(ctx context.Context, out io.Writer, force bool) (string, error) {
		return idp.MintIDToken("test@example.com", time.Now().Add(time.Hour)), nil
	}
}

// testGRPCClient creates a gRPC client connected to the given socket path.
func testGRPCClient(t *testing.T, socketPath string) pb.BrokerServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return pb.NewBrokerServiceClient(conn)
}

// callMatch is a helper that calls Match and returns the result, handling streaming.
func callMatch(t *testing.T, client pb.BrokerServiceClient, req *pb.MatchRequest) *pb.MatchResult {
	t.Helper()
	stream, err := client.Match(context.Background(), req)
	require.NoError(t, err)

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
	require.NotNil(t, result, "no result received from broker")
	return result
}

func Test_RpcBasics(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	idp := oidctest.New(t)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, testTokenFunc(t, idp), testCAClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0) // Skip waiting in tests.

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

	client := testGRPCClient(t, socketPath)
	result := callMatch(t, client, &pb.MatchRequest{})

	// With no agent available, should return false.
	require.False(t, result.Allow)
}

func Test_MatchRequestFields(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	idp := oidctest.New(t)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	caClient := testCAClientOK(t)
	b, err := New(*testLogger(t), socketPath, testTokenFunc(t, idp), caClient, agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0) // Skip waiting in tests.

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

	client := testGRPCClient(t, socketPath)

	// Test with all fields populated.
	req := &pb.MatchRequest{
		Connection: &pb.Connection{
			LocalHost:  "mylaptop.local",
			RemoteHost: "server.example.com",
			RemoteUser: "root",
			Port:       22,
			ProxyJump:  "bastion.example.com",
			Hash:       "abc123def456",
		},
	}

	result := callMatch(t, client, req)

	// The mock CA server doesn't return a valid cert, so we expect an error.
	require.False(t, result.Allow)
	// Error will be about failing to unmarshal CA response (mock doesn't return valid cert).
	require.NotEmpty(t, result.Error)
}

func testLogger(t *testing.T) *slog.Logger {
	logger := slog.New(tint.NewHandler(t.Output(), &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "15:04:05",
	}))
	return logger
}

// shortTempDir creates a short temporary directory suitable for Unix sockets.
// Unix sockets have a path length limit (~104 bytes on macOS), so we use
// /tmp with a short random suffix instead of t.TempDir() which includes
// the full test name and can be too long.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "bt")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestCleanupExpiredAgents(t *testing.T) {
	t.Parallel()
	idp := oidctest.New(t)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, testTokenFunc(t, idp), testCAClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0) // Skip waiting in tests.

	// Manually create agent entries with different expiration times.
	b.lock.Lock()

	// Agent 1: Already expired.
	b.agents[policy.ConnectionHash("expired1")] = agentEntry{
		agent:     nil, // We don't need a real agent for this test.
		expiresAt: time.Now().Add(-10 * time.Second),
	}

	// Agent 2: Expires very soon (within expiryBuffer).
	b.agents[policy.ConnectionHash("expiring-soon")] = agentEntry{
		agent:     nil,
		expiresAt: time.Now().Add(3 * time.Second), // Less than expiryBuffer (5s).
	}

	// Agent 3: Still valid (expires well in the future).
	b.agents[policy.ConnectionHash("valid")] = agentEntry{
		agent:     nil,
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	// Verify we have 3 agents before cleanup.
	require.Equal(t, 3, len(b.agents))
	b.lock.Unlock()

	// Run cleanup.
	b.cleanupExpiredAgentsOnce()

	// Verify cleanup results.
	b.lock.Lock()
	defer b.lock.Unlock()

	// Should have only 1 agent remaining (the valid one).
	require.Equal(t, 1, len(b.agents))

	// The valid agent should still be there.
	_, exists := b.agents[policy.ConnectionHash("valid")]
	require.True(t, exists, "valid agent should not be cleaned up")

	// The expired agents should be gone.
	_, exists = b.agents[policy.ConnectionHash("expired1")]
	require.False(t, exists, "expired agent should be cleaned up")

	_, exists = b.agents[policy.ConnectionHash("expiring-soon")]
	require.False(t, exists, "expiring-soon agent should be cleaned up")
}

// Test_MatchStreamsUserOutput verifies that fd 4 output from the auth script flows
// through the full gRPC Match stream as UserOutput events.
func Test_MatchStreamsUserOutput(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// TokenFunc writes user-visible progress and mints a token.
	idp := oidctest.New(t)
	tokenFn := func(ctx context.Context, out io.Writer, force bool) (string, error) {
		fmt.Fprintln(out, "Visit https://example.com and enter code ABC-123")
		return idp.MintIDToken("test@example.com", time.Now().Add(time.Hour)), nil
	}
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	caClient := testCAClientOK(t)
	b, err := New(*testLogger(t), socketPath, tokenFn, caClient, agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	defer b.Close()
	<-b.Ready()

	client := testGRPCClient(t, socketPath)

	// Call Match directly (not callMatch, which discards UserOutput events).
	stream, err := client.Match(context.Background(), &pb.MatchRequest{
		Connection: &pb.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "user",
			Port:       22,
			Hash:       "stream-test",
		},
	})
	require.NoError(t, err)

	var userOutput bytes.Buffer
	var result *pb.MatchResult
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		switch e := event.Event.(type) {
		case *pb.MatchEvent_UserOutput:
			userOutput.Write(e.UserOutput)
		case *pb.MatchEvent_Result:
			result = e.Result
		}
	}

	require.Contains(t, userOutput.String(), "Visit https://example.com",
		"fd 4 output should be streamed as UserOutput events")
	require.NotNil(t, result, "should receive a MatchResult")
	// Allow will be false because the mock CA can't issue real certs — that's fine,
	// we're testing that user output streams through, not cert issuance.
	require.False(t, result.Allow)
}
