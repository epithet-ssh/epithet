package broker

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/rpc"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
)

// testCAClient creates a test CA client for use in tests
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

	// Create a discovery server
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(caclient.Discovery{MatchPatterns: patterns})
	}))
	t.Cleanup(discoveryServer.Close)

	// Create a CA server that returns the discovery URL in Link header
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

func Test_RpcBasics(t *testing.T) {
	ctx := t.Context()
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:thello,"
`)
	socketPath := t.TempDir() + "/broker.sock"
	agentSocketDir := t.TempDir() + "/sockets"

	b, err := New(*testLogger(t), socketPath, authCommand, testCAClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0) // Skip waiting in tests

	// Serve in background
	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	defer b.Close()

	// Give broker time to start listening
	time.Sleep(10 * time.Millisecond)

	client, err := rpc.Dial("unix", socketPath)
	require.NoError(t, err)

	resp := MatchResponse{}
	err = client.Call("Broker.Match", MatchRequest{}, &resp)
	require.NoError(t, err)

	// With no agent available, should return false
	require.False(t, resp.Allow)
}

func Test_MatchRequestFields(t *testing.T) {
	ctx := t.Context()
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
	socketPath := t.TempDir() + "/broker.sock"
	agentSocketDir := t.TempDir() + "/sockets"

	// Use discovery-enabled CA client
	caClient := testCAClientWithDiscovery(t, []string{"*.example.com"})
	b, err := New(*testLogger(t), socketPath, authCommand, caClient, agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0) // Skip waiting in tests

	// Serve in background
	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	defer b.Close()

	// Give broker time to start listening
	time.Sleep(10 * time.Millisecond)

	client, err := rpc.Dial("unix", socketPath)
	require.NoError(t, err)

	// Test with all fields populated - host matches discovery pattern
	req := MatchRequest{
		Connection: policy.Connection{
			LocalHost:  "mylaptop.local",
			RemoteHost: "server.example.com",
			RemoteUser: "root",
			Port:       22,
			ProxyJump:  "bastion.example.com",
			Hash:       "abc123def456",
		},
	}

	resp := MatchResponse{}
	err = client.Call("Broker.Match", req, &resp)
	require.NoError(t, err)

	// Host matches discovery pattern, but no CA to issue cert
	// The mock CA server doesn't return valid certs, so we expect an error
	require.False(t, resp.Allow)
	// Error will be about failing to unmarshal CA response (mock doesn't return valid cert)
	require.NotEmpty(t, resp.Error)
}

func Test_ShouldHandle(t *testing.T) {
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
			authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
			socketPath := t.TempDir() + "/broker.sock"
			agentSocketDir := t.TempDir() + "/sockets"

			// Use testCAClientWithDiscovery to provide patterns via discovery
			caClient := testCAClientWithDiscovery(t, tt.patterns)

			b, err := New(*testLogger(t), socketPath, authCommand, caClient, agentSocketDir)
			require.NoError(t, err)
			b.SetShutdownTimeout(0) // Skip waiting in tests

			result := b.shouldHandle(tt.hostname)
			require.Equal(t, tt.expected, result, "hostname: %s, patterns: %v", tt.hostname, tt.patterns)
		})
	}
}

func Test_MatchWithPatternFiltering(t *testing.T) {
	ctx := t.Context()
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
	// Use short paths to avoid Unix socket path length limits
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	// Create broker with discovery that only handles *.example.com
	caClient := testCAClientWithDiscovery(t, []string{"*.example.com"})
	b, err := New(*testLogger(t), socketPath, authCommand, caClient, agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0) // Skip waiting in tests

	// Serve in background
	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	defer b.Close()

	time.Sleep(10 * time.Millisecond)

	client, err := rpc.Dial("unix", socketPath)
	require.NoError(t, err)

	// Test 1: Host that matches discovery pattern
	req1 := MatchRequest{
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "user",
			Port:       22,
			Hash:       "hash1",
		},
	}
	resp1 := MatchResponse{}
	err = client.Call("Broker.Match", req1, &resp1)
	require.NoError(t, err)
	// Should proceed past pattern check (will fail later because mock CA doesn't return valid cert)
	require.False(t, resp1.Allow)
	require.NotContains(t, resp1.Error, "does not match") // Pattern matched, failed for other reason

	// Test 2: Host that doesn't match discovery pattern
	req2 := MatchRequest{
		Connection: policy.Connection{
			RemoteHost: "other.com",
			RemoteUser: "user",
			Port:       22,
			Hash:       "hash2",
		},
	}
	resp2 := MatchResponse{}
	err = client.Call("Broker.Match", req2, &resp2)
	require.NoError(t, err)
	// Should be rejected at pattern check
	require.False(t, resp2.Allow)
	require.Contains(t, resp2.Error, "does not match")
}

func testLogger(t *testing.T) *slog.Logger {
	logger := slog.New(tint.NewHandler(t.Output(), &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "15:04:05",
	}))
	return logger
}

func Test_ShouldHandle_UsesDiscoveryPatterns(t *testing.T) {
	// Start a discovery server that returns specific patterns
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"matchPatterns": ["*.example.com"]}`))
	}))
	defer discoveryServer.Close()

	// CA server returns Link header pointing to discovery
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+discoveryServer.URL+`>; rel="discovery"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
	socketPath := t.TempDir() + "/broker.sock"
	agentSocketDir := t.TempDir() + "/sockets"

	client := testCAClient(t, caServer.URL)
	b, err := New(*testLogger(t), socketPath, authCommand, client, agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	// shouldHandle triggers auth + Hello + discovery fetch
	// Discovery patterns should be used for matching
	require.True(t, b.shouldHandle("server.example.com"), "discovery pattern should match *.example.com")
	require.False(t, b.shouldHandle("other.com"), "discovery pattern should not match other.com")
}

func Test_ShouldHandle_NoDiscovery_ReturnsFalse(t *testing.T) {
	// CA server with no discovery URL (no Link header)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Link header - no discovery available
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "test-token"
`)
	socketPath := t.TempDir() + "/broker.sock"
	agentSocketDir := t.TempDir() + "/sockets"

	b, err := New(*testLogger(t), socketPath, authCommand, testCAClient(t, caServer.URL), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	// With no discovery available, shouldHandle returns false for all hosts
	require.False(t, b.shouldHandle("server.example.com"), "no discovery should return false")
	require.False(t, b.shouldHandle("anything.com"), "no discovery should return false")
}

func TestCleanupExpiredAgents(t *testing.T) {
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:thello,"
`)
	socketPath := t.TempDir() + "/broker.sock"
	agentSocketDir := t.TempDir() + "/sockets"

	b, err := New(*testLogger(t), socketPath, authCommand, testCAClient(t, "http://localhost:9999"), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0) // Skip waiting in tests

	// Manually create agent entries with different expiration times
	b.lock.Lock()

	// Agent 1: Already expired
	b.agents[policy.ConnectionHash("expired1")] = agentEntry{
		agent:     nil, // We don't need a real agent for this test
		expiresAt: time.Now().Add(-10 * time.Second),
	}

	// Agent 2: Expires very soon (within expiryBuffer)
	b.agents[policy.ConnectionHash("expiring-soon")] = agentEntry{
		agent:     nil,
		expiresAt: time.Now().Add(3 * time.Second), // Less than expiryBuffer (5s)
	}

	// Agent 3: Still valid (expires well in the future)
	b.agents[policy.ConnectionHash("valid")] = agentEntry{
		agent:     nil,
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	// Verify we have 3 agents before cleanup
	require.Equal(t, 3, len(b.agents))
	b.lock.Unlock()

	// Run cleanup
	b.cleanupExpiredAgentsOnce()

	// Verify cleanup results
	b.lock.Lock()
	defer b.lock.Unlock()

	// Should have only 1 agent remaining (the valid one)
	require.Equal(t, 1, len(b.agents))

	// The valid agent should still be there
	_, exists := b.agents[policy.ConnectionHash("valid")]
	require.True(t, exists, "valid agent should not be cleaned up")

	// The expired agents should be gone
	_, exists = b.agents[policy.ConnectionHash("expired1")]
	require.False(t, exists, "expired agent should be cleaned up")

	_, exists = b.agents[policy.ConnectionHash("expiring-soon")]
	require.False(t, exists, "expiring-soon agent should be cleaned up")
}
