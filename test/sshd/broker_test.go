package sshd_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
)

// TestBrokerEndToEnd tests the complete flow:
// 1. Start broker with auth command
// 2. Start CA server
// 3. Start sshd server
// 4. Broker requests certificate from CA
// 5. Broker creates per-connection agent
// 6. SSH connects using broker's agent
func TestBrokerEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := testLogger(t)

	// Generate CA key pair
	caPublicKey, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	// Create a mock policy server that approves everything
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple policy that approves all requests
		// The principals must match what's in the sshd auth_principals file
		// which is generated in sshd.go:generateConfigs() as "a\nb"
		resp := ca.PolicyResponse{
			CertParams: ca.CertParams{
				Identity:   "test-user",
				Names:      []string{"a", "b"}, // Match the auth_principals file
				Expiration: 5 * time.Minute,
				Extensions: map[string]string{
					"permit-pty": "",
				},
			},
			Policy: policy.Policy{
				HostUsers: map[string][]string{
					"*": {"a", "b"}, // Accept all hosts for these users
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer policyServer.Close()

	// Create CA
	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	// Start CA server
	caHTTPServer := httptest.NewServer(caserver.New(caInstance, logger, nil, nil))
	defer caHTTPServer.Close()

	// Create auth command that returns a fake token
	authScript := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:ttoken,"
`)

	// Create broker with short paths to avoid Unix socket path length limits
	tmpDir := t.TempDir()
	brokerSocketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a" // Very short to avoid socket path length issues
	matchPatterns := []string{"*"}  // Accept all hosts
	b := broker.New(*logger, brokerSocketPath, authScript, caHTTPServer.URL, agentSocketDir, matchPatterns)

	// Start broker in background
	go func() {
		err := b.Serve(ctx)
		if err != nil && err != context.Canceled {
			t.Logf("broker serve error: %v", err)
		}
	}()
	defer b.Close()

	// Give broker time to start
	time.Sleep(50 * time.Millisecond)

	// Start sshd server
	sshdServer, err := sshd.Start(caPublicKey)
	require.NoError(t, err)
	defer sshdServer.Close()

	t.Logf("SSHD started on port %d", sshdServer.Port)

	// Now simulate what epithet match would do: call broker.Match
	req := broker.MatchRequest{
		Connection: policy.Connection{
			LocalHost:  "localhost",
			RemoteHost: "localhost",
			RemoteUser: sshdServer.User,
			Port:       uint(sshdServer.Port),
			ProxyJump:  "",
			Hash:       computeConnectionHash(t, sshdServer),
		},
	}

	var resp broker.MatchResponse
	// In a real scenario, this would be done via RPC, but we can call directly for testing
	err = b.Match(req, &resp)
	require.NoError(t, err)
	t.Logf("Match response: Allow=%v, Error=%s", resp.Allow, resp.Error)
	require.True(t, resp.Allow, "broker should allow connection: %s", resp.Error)

	// Give agent time to start
	time.Sleep(100 * time.Millisecond)

	// Check if agent socket exists
	agentSocket := b.AgentSocketPath(req.Connection.Hash)
	t.Logf("Agent socket path: %s", agentSocket)
	_, err = os.Stat(agentSocket)
	if err != nil {
		t.Logf("Agent socket stat error: %v", err)
	} else {
		t.Logf("Agent socket exists")
	}

	// Now try to SSH using the broker's agent
	out, err := sshdServer.SshWithBroker(b)
	if err != nil {
		t.Logf("SSH output:\n%s", out)
		t.Logf("SSHD output:\n%s", sshdServer.Output.String())
	}
	require.NoError(t, err, "SSH connection should succeed")

	t.Logf("SSH succeeded! Output:\n%s", out)
}

func writeTestScript(t *testing.T, script string) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "auth-script-*.sh")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpfile.Name()) })

	_, err = tmpfile.Write([]byte(script))
	require.NoError(t, err)

	err = tmpfile.Close()
	require.NoError(t, err)

	err = os.Chmod(tmpfile.Name(), 0700)
	require.NoError(t, err)

	return tmpfile.Name()
}

func testLogger(t *testing.T) *slog.Logger {
	return slog.New(tint.NewHandler(t.Output(), &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "15:04:05",
	}))
}

func computeConnectionHash(t *testing.T, s *sshd.Server) policy.ConnectionHash {
	// This must match the hash computation in SshWithBroker
	localHost, err := os.Hostname()
	require.NoError(t, err)

	hashInput := fmt.Sprintf("%slocalhost%d%s", localHost, s.Port, s.User)
	hash := sha256.Sum256([]byte(hashInput))
	return policy.ConnectionHash(hex.EncodeToString(hash[:])[:16])
}
