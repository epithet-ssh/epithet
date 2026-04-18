package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	pb "github.com/epithet-ssh/epithet/pkg/brokerv1"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
	sshagent "golang.org/x/crypto/ssh/agent"
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

// testCAClientWithDiscovery creates a CA client with a mock discovery endpoint.
// The discovery patterns are returned by the mock CA's Hello endpoint.
func testCAClientWithDiscovery(t *testing.T, patterns []string) *caclient.Client {
	t.Helper()

	// Create a discovery server.
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(caclient.Discovery{MatchPatterns: patterns})
	}))
	t.Cleanup(discoveryServer.Close)

	// Create a CA server that returns the discovery URL in Link header.
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+discoveryServer.URL+`>; rel="discovery"`)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(caServer.Close)

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	if err != nil {
		t.Fatalf("failed to create test CA client: %v", err)
	}
	return client
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
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:thello,"
`)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, authCommand, testCAClient(t, "http://localhost:9999"), agentSocketDir)
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
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	// Use discovery-enabled CA client.
	caClient := testCAClientWithDiscovery(t, []string{"*.example.com"})
	b, err := New(*testLogger(t), socketPath, authCommand, caClient, agentSocketDir)
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

	// Test with all fields populated - host matches discovery pattern.
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

	// Host matches discovery pattern, but no CA to issue cert.
	// The mock CA server doesn't return valid certs, so we expect an error.
	require.False(t, result.Allow)
	// Error will be about failing to unmarshal CA response (mock doesn't return valid cert).
	require.NotEmpty(t, result.Error)
}

func Test_ShouldHandle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		patterns []string
		hostname string
		expected bool
	}{
		{
			name:     "exact match",
			patterns: []string{"example.com"},
			hostname: "example.com",
			expected: true,
		},
		{
			name:     "wildcard match",
			patterns: []string{"*.example.com"},
			hostname: "server.example.com",
			expected: true,
		},
		{
			name:     "multiple patterns - first matches",
			patterns: []string{"*.example.com", "*.test.com"},
			hostname: "server.example.com",
			expected: true,
		},
		{
			name:     "multiple patterns - second matches",
			patterns: []string{"*.example.com", "*.test.com"},
			hostname: "host.test.com",
			expected: true,
		},
		{
			name:     "no match",
			patterns: []string{"*.example.com"},
			hostname: "other.com",
			expected: false,
		},
		{
			name:     "wildcard all",
			patterns: []string{"*"},
			hostname: "anything.com",
			expected: true,
		},
		{
			name:     "complex pattern",
			patterns: []string{"server-*.prod.example.com"},
			hostname: "server-01.prod.example.com",
			expected: true,
		},
		{
			name:     "complex pattern - no match",
			patterns: []string{"server-*.prod.example.com"},
			hostname: "server-01.dev.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
			// Use short paths to avoid Unix socket path length limits.
			tmpDir := shortTempDir(t)
			socketPath := tmpDir + "/b.sock"
			agentSocketDir := tmpDir + "/a"

			// Use testCAClientWithDiscovery to provide patterns via discovery.
			caClient := testCAClientWithDiscovery(t, tt.patterns)

			b, err := New(*testLogger(t), socketPath, authCommand, caClient, agentSocketDir)
			require.NoError(t, err)
			b.SetShutdownTimeout(0) // Skip waiting in tests.

			result := b.shouldHandle(tt.hostname, nil)
			require.Equal(t, tt.expected, result, "hostname: %s, patterns: %v", tt.hostname, tt.patterns)
		})
	}
}

func Test_MatchWithPatternFiltering(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	// Create broker with discovery that only handles *.example.com.
	caClient := testCAClientWithDiscovery(t, []string{"*.example.com"})
	b, err := New(*testLogger(t), socketPath, authCommand, caClient, agentSocketDir)
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

	// Test 1: Host that matches discovery pattern.
	req1 := &pb.MatchRequest{
		Connection: &pb.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "user",
			Port:       22,
			Hash:       "hash1",
		},
	}
	result1 := callMatch(t, client, req1)
	// Should proceed past pattern check (will fail later because mock CA doesn't return valid cert).
	require.False(t, result1.Allow)
	require.NotContains(t, result1.Error, "does not match") // Pattern matched, failed for other reason.

	// Test 2: Host that doesn't match discovery pattern.
	req2 := &pb.MatchRequest{
		Connection: &pb.Connection{
			RemoteHost: "other.com",
			RemoteUser: "user",
			Port:       22,
			Hash:       "hash2",
		},
	}
	result2 := callMatch(t, client, req2)
	// Should be rejected at pattern check - Allow=false, no error (not an error condition).
	require.False(t, result2.Allow)
	require.Empty(t, result2.Error)
}

func TestAuthenticate_WithUpstream(t *testing.T) {
	t.Parallel()

	// Start an upstream agent that serves epithet-auth.
	upstreamSock := startUpstreamAuthAgent(t, "upstream-token-from-test")

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentDir := tmpDir + "/a"

	// Local auth should NOT be called — upstream provides the token.
	localAuthScript := writeTestScript(t, `#!/bin/sh
echo "ERROR: local auth should not have been called" >&2
exit 1
`)
	b, err := New(*testLogger(t), socketPath, localAuthScript, testCAClient(t, "http://localhost:9999"), agentDir, WithUpstream(upstreamSock))
	require.NoError(t, err)

	token, err := b.Authenticate(nil)
	require.NoError(t, err)
	require.Equal(t, "upstream-token-from-test", token)

	// Token should be cached in auth.
	require.Equal(t, "upstream-token-from-test", b.auth.Token())
}

func TestAuthenticate_FallsBackToLocal(t *testing.T) {
	t.Parallel()

	// Start an upstream agent that does NOT serve epithet-auth (no extensions).
	upstreamSock := startPlainAgent(t)

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentDir := tmpDir + "/a"

	// Local auth will be called as fallback.
	localAuthScript := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "local-fallback-token"
`)
	b, err := New(*testLogger(t), socketPath, localAuthScript, testCAClient(t, "http://localhost:9999"), agentDir, WithUpstream(upstreamSock))
	require.NoError(t, err)

	token, err := b.Authenticate(nil)
	require.NoError(t, err)
	// Local auth base64url-encodes the token.
	require.NotEmpty(t, token)
}

func TestAuthenticate_NoUpstream(t *testing.T) {
	t.Parallel()

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentDir := tmpDir + "/a"

	localAuthScript := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "local-only-token"
`)
	// No WithUpstream — should go straight to local auth.
	b, err := New(*testLogger(t), socketPath, localAuthScript, testCAClient(t, "http://localhost:9999"), agentDir)
	require.NoError(t, err)

	token, err := b.Authenticate(nil)
	require.NoError(t, err)
	require.NotEmpty(t, token)
}

func TestAuthenticate_UpstreamAuthFailure_NoFallback(t *testing.T) {
	t.Parallel()

	// Start an upstream agent whose auth handler returns an error.
	upstreamSock := startUpstreamFailingAuthAgent(t)

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentDir := tmpDir + "/a"

	// Local auth should NOT be called — upstream failure should propagate.
	localAuthScript := writeTestScript(t, `#!/bin/sh
echo "ERROR: local auth should not have been called" >&2
exit 1
`)
	b, err := New(*testLogger(t), socketPath, localAuthScript, testCAClient(t, "http://localhost:9999"), agentDir, WithUpstream(upstreamSock))
	require.NoError(t, err)

	_, err = b.Authenticate(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "upstream auth failed")
}

// startUpstreamFailingAuthAgent starts a proxy agent whose auth handler always fails.
func startUpstreamFailingAuthAgent(t *testing.T) string {
	t.Helper()

	tmpDir := shortTempDir(t)
	upstreamSock := tmpDir + "/upstream.sock"
	vanillaSock := tmpDir + "/vanilla.sock"

	vanillaListener, err := net.Listen("unix", vanillaSock)
	require.NoError(t, err)
	t.Cleanup(func() { vanillaListener.Close() })

	keyring := sshagent.NewKeyring()
	go func() {
		for {
			conn, err := vanillaListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sshagent.ServeAgent(keyring, c)
			}(conn)
		}
	}()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	setup := func(p *agent.ProxyAgent) {
		p.RegisterExtension(agent.ExtensionAuth, agent.AuthHandler(func() (string, error) {
			return "", fmt.Errorf("user cancelled authentication")
		}))
	}
	proxy := agent.NewProxyListener(logger, upstreamSock, vanillaSock, setup)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go proxy.Serve(ctx)
	<-proxy.Ready()

	return upstreamSock
}

// startUpstreamAuthAgent starts a proxy agent that handles epithet-auth and returns the given token.
func startUpstreamAuthAgent(t *testing.T, token string) string {
	t.Helper()

	tmpDir := shortTempDir(t)
	upstreamSock := tmpDir + "/upstream.sock"
	vanillaSock := tmpDir + "/vanilla.sock"

	// Start a vanilla agent as the upstream's upstream.
	vanillaListener, err := net.Listen("unix", vanillaSock)
	require.NoError(t, err)
	t.Cleanup(func() { vanillaListener.Close() })

	keyring := sshagent.NewKeyring()
	go func() {
		for {
			conn, err := vanillaListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sshagent.ServeAgent(keyring, c)
			}(conn)
		}
	}()

	// Start the proxy listener with auth handler.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	setup := func(p *agent.ProxyAgent) {
		p.RegisterExtension(agent.ExtensionAuth, agent.AuthHandler(func() (string, error) {
			return token, nil
		}))
	}
	proxy := agent.NewProxyListener(logger, upstreamSock, vanillaSock, setup)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go proxy.Serve(ctx)
	<-proxy.Ready()

	return upstreamSock
}

// startPlainAgent starts a vanilla ssh-agent (no epithet extensions).
func startPlainAgent(t *testing.T) string {
	t.Helper()

	tmpDir := shortTempDir(t)
	sockPath := tmpDir + "/plain.sock"

	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	keyring := sshagent.NewKeyring()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sshagent.ServeAgent(keyring, c)
			}(conn)
		}
	}()

	return sockPath
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

func Test_ShouldHandle_UsesDiscoveryPatterns(t *testing.T) {
	t.Parallel()
	// Start a discovery server that returns specific patterns.
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"matchPatterns": ["*.example.com"]}`))
	}))
	defer discoveryServer.Close()

	// CA server returns Link header pointing to discovery.
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+discoveryServer.URL+`>; rel="discovery"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	client := testCAClient(t, caServer.URL)
	b, err := New(*testLogger(t), socketPath, authCommand, client, agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	// shouldHandle triggers auth + Hello + discovery fetch.
	// Discovery patterns should be used for matching.
	require.True(t, b.shouldHandle("server.example.com", nil), "discovery pattern should match *.example.com")
	require.False(t, b.shouldHandle("other.com", nil), "discovery pattern should not match other.com")
}

func Test_ShouldHandle_NoDiscovery_ReturnsFalse(t *testing.T) {
	t.Parallel()
	// CA server with no discovery URL (no Link header).
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Link header - no discovery available.
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, authCommand, testCAClient(t, caServer.URL), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	// With no discovery available, shouldHandle returns false for all hosts.
	require.False(t, b.shouldHandle("server.example.com", nil), "no discovery should return false")
	require.False(t, b.shouldHandle("anything.com", nil), "no discovery should return false")
}

func TestCleanupExpiredAgents(t *testing.T) {
	t.Parallel()
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:thello,"
`)
	// Use short paths to avoid Unix socket path length limits.
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, authCommand, testCAClient(t, "http://localhost:9999"), agentSocketDir)
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

	// Auth script writes to fd 4 (user output) and stdout (token).
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
echo "Visit https://example.com and enter code ABC-123" >&4
printf '%s' "test-token"
`)
	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	// Discovery-enabled CA so the match proceeds past shouldHandle.
	caClient := testCAClientWithDiscovery(t, []string{"*.example.com"})
	b, err := New(*testLogger(t), socketPath, authCommand, caClient, agentSocketDir)
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

// Test_DiscoveryReauthOnExpiredToken verifies that when a cached auth token has
// expired at the server, getDiscoveryPatterns re-authenticates and retries Hello
// instead of failing the match.
func Test_DiscoveryReauthOnExpiredToken(t *testing.T) {
	t.Parallel()

	// Track whether the CA should reject the current token.
	var rejectToken sync.Mutex
	tokenExpired := false

	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No caching so each call hits the server.
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(caclient.Discovery{MatchPatterns: []string{"*.example.com"}})
	}))
	defer discoveryServer.Close()

	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rejectToken.Lock()
		expired := tokenExpired
		rejectToken.Unlock()

		if expired && r.Header.Get("Authorization") == "Bearer dG9rZW4tMQ" {
			// First token ("token-1" base64url) is expired — return 401.
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("token expired"))
			return
		}
		w.Header().Set("Link", `<`+discoveryServer.URL+`>; rel="discovery"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	// Auth script that returns different tokens on each invocation.
	// Uses a counter file to produce token-1, token-2, etc.
	countFile := t.TempDir() + "/auth_count"
	authCommand := writeTestScript(t, fmt.Sprintf(`#!/bin/sh
cat > /dev/null
count_file="%s"
if [ -f "$count_file" ]; then
    count=$(cat "$count_file")
else
    count=0
fi
count=$((count + 1))
echo "$count" > "$count_file"
printf "token-%%d" "$count"
`, countFile))

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	client := testCAClient(t, caServer.URL)
	b, err := New(*testLogger(t), socketPath, authCommand, client, agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	// First call: should succeed — fresh token, Hello accepts it.
	result := b.shouldHandle("server.example.com", nil)
	require.True(t, result, "first call should succeed with fresh token")

	// Simulate token expiry at the server.
	rejectToken.Lock()
	tokenExpired = true
	rejectToken.Unlock()

	// Clear the cached discovery URL so getDiscoveryPatterns must go through Hello again.
	client.SetDiscoveryURL("")

	// Second call: token-1 is now rejected. Broker should re-auth (get token-2) and succeed.
	result = b.shouldHandle("server.example.com", nil)
	require.True(t, result, "should succeed after re-authenticating with new token")
}

// Test_UserOutputStreaming tests that user output from fd 4 is streamed to the writer.
func Test_UserOutputStreaming(t *testing.T) {
	t.Parallel()

	// Test the underlying Run method with user output writer directly since the
	// full Match flow requires complex CA setup. The gRPC streaming layer is
	// tested in the other Match tests.
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
echo "Visit https://example.com and enter code ABC-123" >&4
printf '%s' "test-token"
`)
	auth := NewAuth(script)

	var userOutput bytes.Buffer
	token, err := auth.Run(nil, &userOutput)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.Contains(t, userOutput.String(), "Visit https://example.com")
}
