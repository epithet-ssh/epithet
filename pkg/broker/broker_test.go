package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
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

// callMatch dials socketPath, sends a Match request for conn, and returns
// the terminal Result event (discarding any Output events along the way).
func callMatch(t *testing.T, socketPath string, conn policy.Connection) *MatchResponse {
	t.Helper()
	c, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer c.Close()

	require.NoError(t, json.NewEncoder(c).Encode(Request{Match: &conn}))

	sc := bufio.NewScanner(c)
	for sc.Scan() {
		var ev Event
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
		if ev.Result != nil {
			return ev.Result
		}
	}
	t.Fatal("no result received from broker")
	return nil
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

	result := callMatch(t, socketPath, policy.Connection{})

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

	// Test with all fields populated.
	result := callMatch(t, socketPath, policy.Connection{
		RemoteHost: "server.example.com",
		RemoteUser: "root",
		Port:       22,
		ProxyJump:  "bastion.example.com",
		Hash:       "abc123def456",
	})

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

// Test_MatchStreamsUserOutput's coverage (fd 4 auth output streams through
// to the client before the terminal result) moved to protocol_test.go's
// TestMatchStreamsOutputThenResult when the broker IPC switched from gRPC
// streaming to newline-framed JSON.

// countingHandler wraps h, incrementing hits on every request that reaches
// it. Used to prove a CA hit count end to end, not just that a match succeeded.
func countingHandler(hits *int32, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		h.ServeHTTP(w, r)
	})
}

// realCAAndPolicy wires a real ca.CA, a real policyserver.NewHandler (real
// OIDC validator against idp + a real evaluator), and a counting wrapper
// around the CA's HTTP handler. It returns the CA HTTP server's URL and the
// hit counter, so callers can assert exactly how many times the CA was
// actually asked to mint a certificate - not just that the broker's match
// calls succeeded.
func realCAAndPolicy(t *testing.T, idp *oidctest.IdP, policyCfg *policyserver.PolicyConfig) (caURL string, hits *int32) {
	t.Helper()

	caPub, caPriv, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	validator, err := oidc.NewValidator(context.Background(), oidc.Config{
		Issuer:   idp.Issuer(),
		ClientID: oidctest.ClientID,
	})
	require.NoError(t, err)

	policyHandler, err := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: caPub,
		Validator:   validator,
		Evaluator:   evaluator.NewForTesting(policyCfg),
	})
	require.NoError(t, err)
	policySrv := httptest.NewServer(policyHandler)
	t.Cleanup(policySrv.Close)

	caInstance, err := ca.New(caPriv, policySrv.URL)
	require.NoError(t, err)

	casrv := caserver.New(caInstance, testLogger(t), nil)
	hits = new(int32)
	mux := http.NewServeMux()
	mux.Handle("/", countingHandler(hits, casrv.Handler()))
	caHTTPServer := httptest.NewServer(mux)
	t.Cleanup(caHTTPServer.Close)

	return caHTTPServer.URL, hits
}

// TestMatchFanOut_ThreeHostsThreeCAHits verifies the deletion-risk case from
// spec §10: matching three distinct hosts under one shared policy mints
// three separate certificates - one CA request per connection, never cached
// or reused across connections (see Task 11b) - and each cert carries
// exactly the principal requested for its own connection, never a union of
// all three.
func TestMatchFanOut_ThreeHostsThreeCAHits(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	idp := oidctest.New(t)

	policyCfg := &policyserver.PolicyConfig{
		Users: map[string][]string{"test@example.com": {"member"}},
		Defaults: &policyserver.Rules{
			Allow:      map[string][]string{"alice": {"member"}, "bob": {"member"}, "carol": {"member"}},
			Expiration: "5m",
		},
		Hosts: map[string]*policyserver.Rules{"*": {}},
	}
	caURL, hits := realCAAndPolicy(t, idp, policyCfg)

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, testTokenFunc(t, idp), testCAClient(t, caURL), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	t.Cleanup(b.Close)
	<-b.Ready()

	conns := []policy.Connection{
		{RemoteHost: "host-a.example.com", RemoteUser: "alice", Hash: "hash-a"},
		{RemoteHost: "host-b.example.com", RemoteUser: "bob", Hash: "hash-b"},
		{RemoteHost: "host-c.example.com", RemoteUser: "carol", Hash: "hash-c"},
	}
	for _, conn := range conns {
		result := callMatch(t, socketPath, conn)
		require.True(t, result.Allow, "match for %s should be allowed: %s", conn.RemoteHost, result.Error)
	}

	require.Equal(t, int32(3), atomic.LoadInt32(hits), "expected exactly one CA hit per connection")

	// Each connection's agent carries a cert naming exactly its own
	// requested principal - not the union of alice/bob/carol.
	b.lock.Lock()
	defer b.lock.Unlock()
	require.Len(t, b.agents, 3)
	for _, conn := range conns {
		entry, ok := b.agents[conn.Hash]
		require.True(t, ok, "expected an agent for %s", conn.Hash)
		cert, err := sshcert.Parse(entry.certificate)
		require.NoError(t, err)
		require.Equal(t, []string{conn.RemoteUser}, cert.ValidPrincipals,
			"cert for %s must name only the requested principal", conn.RemoteHost)
	}
}

// TestMatchCADown_ReturnsHumanLegibleError covers the other deletion-risk
// case from spec §10: when the CA is completely unreachable (the port is
// closed, not merely erroring), the match must be denied with a non-empty
// error that mentions the CA - this is the text a user actually sees via
// ssh, not an opaque internal error.
func TestMatchCADown_ReturnsHumanLegibleError(t *testing.T) {
	t.Parallel()
	idp := oidctest.New(t)

	// Bind and immediately close a TCP port: nothing is listening there, so
	// every request fails fast at the TCP level (connection refused) rather
	// than hanging or getting an HTTP error response.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := ln.Addr().String()
	require.NoError(t, ln.Close())

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	caClient := testCAClient(t, "http://"+closedAddr)
	b, err := New(*testLogger(t), socketPath, testTokenFunc(t, idp), caClient, agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0)

	ctx := t.Context()
	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	t.Cleanup(b.Close)
	<-b.Ready()

	resp := b.MatchWithUserOutput(ctx, policy.Connection{
		RemoteHost: "down.example.com",
		RemoteUser: "root",
		Hash:       "downhash",
	}, nil)

	require.False(t, resp.Allow)
	require.NotEmpty(t, resp.Error)
	require.Contains(t, resp.Error, "CA", "error should mention the CA so it reads clearly via ssh")
}
