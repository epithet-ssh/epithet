package broker

import (
	"log/slog"
	"net/rpc"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
)

func Test_RpcBasics(t *testing.T) {
	ctx := t.Context()
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:thello,"
`)
	socketPath := t.TempDir() + "/broker.sock"
	agentSocketDir := t.TempDir() + "/sockets"

	b := New(*testLogger(t), socketPath, authCommand, "http://localhost:9999", agentSocketDir, []string{"*"})

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
printf '%s' "6:thello,"
`)
	socketPath := t.TempDir() + "/broker.sock"
	agentSocketDir := t.TempDir() + "/sockets"

	b := New(*testLogger(t), socketPath, authCommand, "http://localhost:9999", agentSocketDir, []string{"*"})

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

	// Test with all fields populated
	req := MatchRequest{
		Connection: policy.Connection{
			LocalHost:  "mylaptop.local",
			LocalUser:  "alice",
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

	// With no CA available, should return false with error
	require.False(t, resp.Allow)
	require.Contains(t, resp.Error, "failed to request certificate")
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
printf '%s' "6:thello,"
`)
			socketPath := t.TempDir() + "/broker.sock"
			agentSocketDir := t.TempDir() + "/sockets"

			b := New(*testLogger(t), socketPath, authCommand, "http://localhost:9999", agentSocketDir, tt.patterns)

			result := b.shouldHandle(tt.hostname)
			require.Equal(t, tt.expected, result, "hostname: %s, patterns: %v", tt.hostname, tt.patterns)
		})
	}
}

func Test_MatchWithPatternFiltering(t *testing.T) {
	ctx := t.Context()
	authCommand := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:thello,"
`)
	// Use short paths to avoid Unix socket path length limits
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	// Create broker that only handles *.example.com
	patterns := []string{"*.example.com"}
	b := New(*testLogger(t), socketPath, authCommand, "http://localhost:9999", agentSocketDir, patterns)

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

	// Test 1: Host that matches pattern
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
	// Should proceed past pattern check (will fail later for other reasons)
	require.False(t, resp1.Allow)
	require.Contains(t, resp1.Error, "failed to request certificate") // Not "does not match"

	// Test 2: Host that doesn't match pattern
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
	require.Contains(t, resp2.Error, "does not match any configured patterns")
}

func testLogger(t *testing.T) *slog.Logger {
	logger := slog.New(tint.NewHandler(t.Output(), &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "15:04:05",
	}))
	return logger
}
