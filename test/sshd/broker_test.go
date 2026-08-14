package sshd_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
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
	// Previously skipped pending Task 14's Hello/Link removal (that gating
	// path no longer exists in pkg/broker/broker.go as of Task 11's match
	// path collapse). Re-enabled: this exercises the real caclient/caserver
	// wire path with an in-process TokenFunc. Note the mock policy server
	// approves every request unconditionally, so it never actually verifies
	// the JWT against the discovery issuer — a real token-verification test
	// belongs to the policy server package, not here.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := testLogger(t)

	// Generate CA key pair
	caPublicKey, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	// Create a mock policy server that handles both discovery (GET) and cert eval (POST).
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			// Discovery response — CA fetches this for /discovery. The
			// slim anonymous-bootstrap shape (Task 8): auth config only,
			// no server-advertised match patterns.
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]string{
					"issuer":    "https://idp.example.com",
					"client_id": "test-client",
				},
			})
			return
		}
		// POST: cert evaluation — approves all requests.
		// Principals must match the sshd auth_principals file ("a\nb").
		resp := wire.PolicyResponse{
			CertParams: wire.CertParams{
				Identity:   "test-user",
				Names:      []string{"a", "b"},
				Expiration: 5 * time.Minute,
				Extensions: map[string]string{
					"permit-pty": "",
				},
			},
			Policy: policy.Policy{
				HostUsers: map[string][]string{
					"*": {"a", "b"},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer policyServer.Close()

	// Create CA
	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	// Start CA server.
	casrv := caserver.New(caInstance, logger, nil, nil)
	mux := http.NewServeMux()
	mux.Handle("/", casrv.Handler())
	mux.Handle("/discovery", casrv.DiscoveryHandler())
	caHTTPServer := httptest.NewServer(mux)
	defer caHTTPServer.Close()

	// TokenFunc mints a real JWT via an in-process fake IdP.
	idp := oidctest.New(t)
	tokenFn := func(ctx context.Context, out io.Writer, force bool) (string, error) {
		return idp.MintIDToken("test@example.com", time.Now().Add(time.Hour)), nil
	}

	// Create broker with short paths to avoid Unix socket path length limits
	tmpDir := t.TempDir()
	brokerSocketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a" // Very short to avoid socket path length issues

	// Create CA client
	caEndpoints := []caclient.CAEndpoint{{URL: caHTTPServer.URL, Priority: caclient.DefaultPriority}}
	caClient, err := caclient.New(caEndpoints)
	require.NoError(t, err)

	b, err := broker.New(*logger, brokerSocketPath, tokenFn, caClient, agentSocketDir)
	require.NoError(t, err)

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

	// Now simulate what epithet match would do: call broker.MatchWithUserOutput directly.
	conn := policy.Connection{
		LocalHost:  "localhost",
		RemoteHost: "localhost",
		RemoteUser: sshdServer.User,
		Port:       uint(sshdServer.Port),
		ProxyJump:  "",
		Hash:       computeConnectionHash(t, sshdServer),
	}

	// In a real scenario, this would be done via RPC, but we can call directly for testing.
	resp := b.MatchWithUserOutput(ctx, conn, nil)
	t.Logf("Match response: Allow=%v, Error=%s", resp.Allow, resp.Error)
	require.True(t, resp.Allow, "broker should allow connection: %s", resp.Error)

	// Give agent time to start
	time.Sleep(100 * time.Millisecond)

	// Check if agent socket exists
	agentSocket := b.AgentSocketPath(conn.Hash)
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
