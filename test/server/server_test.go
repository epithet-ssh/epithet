package server_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// TestServerEndToEnd verifies the combined server command starts CA and policy
// subprocesses and routes requests correctly through the reverse proxy.
func TestServerEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Mock OIDC server — serves the two endpoints coreos/go-oidc needs
	// for provider discovery: the openid-configuration and an empty JWKS.
	var mockURL string
	mockOIDC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"issuer": %q,
				"jwks_uri": %q,
				"authorization_endpoint": %q,
				"token_endpoint": %q,
				"response_types_supported": ["code"]
			}`, mockURL, mockURL+"/jwks", mockURL+"/auth", mockURL+"/token")
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	mockURL = mockOIDC.URL
	defer mockOIDC.Close()

	// Build the epithet binary.
	tmpDir := shortTempDir(t)
	epithetBin := filepath.Join(tmpDir, "epithet")
	buildCmd := exec.Command("go", "build", "-o", epithetBin, "../../cmd/epithet")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build epithet: %v\n%s", err, output)
	}

	// Generate a CA key pair for the test.
	caPubkey, caPrivkey, err := sshcert.GenerateKeys()
	if err != nil {
		t.Fatalf("failed to generate CA keys: %v", err)
	}

	caKeyPath := filepath.Join(tmpDir, "ca.key")
	if err := os.WriteFile(caKeyPath, []byte(caPrivkey), 0600); err != nil {
		t.Fatalf("failed to write CA key: %v", err)
	}

	// Write config YAML.
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`ca:
  key: %s
  policy: "placeholder"
policy:
  ca_pubkey: "%s"
  oidc:
    issuer: "%s"
    client_id: "test-client"
  users:
    test@example.com: [admin]
  defaults:
    allow:
      root: [admin]
    expiration: "5m"
`, caKeyPath, strings.TrimSpace(string(caPubkey)), mockURL)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Find an available TCP port.
	port := availablePort(t)

	// Start the server. t.Context() cancels when the test ends,
	// which ensures the process is killed if the test fails early.
	serverCmd := exec.CommandContext(t.Context(), epithetBin,
		"--config", configPath,
		"server",
		"--listen", fmt.Sprintf(":%d", port),
		"-v",
	)
	serverCmd.Stdout = os.Stderr
	serverCmd.Stderr = os.Stderr

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Wait for the server to accept TCP connections.
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	waitForTCP(t, fmt.Sprintf("localhost:%d", port), 15*time.Second)

	// Use a client that doesn't follow redirects so we can inspect 302 responses.
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// GET / → 200, body = CA public key (routed to CA subprocess).
	t.Run("ca_pubkey", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/")
		if err != nil {
			t.Fatalf("GET / failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
		}

		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		got := strings.TrimSpace(string(body[:n]))
		want := strings.TrimSpace(string(caPubkey))
		if got != want {
			t.Errorf("GET / body = %q, want %q", got, want)
		}
	})

	// GET /d/current (no auth) → 302 with Location containing /d/.
	t.Run("discovery_redirect_unauth", func(t *testing.T) {
		resp, err := noRedirectClient.Get(baseURL + "/d/current")
		if err != nil {
			t.Fatalf("GET /d/current failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 302 {
			t.Fatalf("GET /d/current status = %d, want 302", resp.StatusCode)
		}

		location := resp.Header.Get("Location")
		if !strings.Contains(location, "/d/") {
			t.Errorf("Location = %q, want it to contain /d/", location)
		}
	})

	// GET /d/current with Authorization header → 302 with a different Location hash.
	t.Run("discovery_redirect_auth", func(t *testing.T) {
		// First get the unauthenticated redirect location.
		unauthResp, err := noRedirectClient.Get(baseURL + "/d/current")
		if err != nil {
			t.Fatalf("unauth GET /d/current failed: %v", err)
		}
		unauthResp.Body.Close()
		unauthLocation := unauthResp.Header.Get("Location")

		// Now with an Authorization header.
		req, _ := http.NewRequest("GET", baseURL+"/d/current", nil)
		req.Header.Set("Authorization", "Bearer x")
		authResp, err := noRedirectClient.Do(req)
		if err != nil {
			t.Fatalf("auth GET /d/current failed: %v", err)
		}
		authResp.Body.Close()

		if authResp.StatusCode != 302 {
			t.Fatalf("auth GET /d/current status = %d, want 302", authResp.StatusCode)
		}

		authLocation := authResp.Header.Get("Location")
		if !strings.Contains(authLocation, "/d/") {
			t.Errorf("auth Location = %q, want it to contain /d/", authLocation)
		}
		if authLocation == unauthLocation {
			t.Errorf("auth and unauth redirects are the same (%s); expected different hashes", authLocation)
		}
	})

	// Shutdown: send SIGTERM and wait for clean exit.
	t.Run("clean_shutdown", func(t *testing.T) {
		if err := serverCmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("failed to send SIGTERM: %v", err)
		}

		done := make(chan error, 1)
		go func() {
			done <- serverCmd.Wait()
		}()

		select {
		case err := <-done:
			// Process should exit cleanly (exit code 0 or signal termination).
			if err != nil {
				// On macOS/Linux, SIGTERM causes an exit error — that's fine.
				if exitErr, ok := err.(*exec.ExitError); ok {
					t.Logf("server exited with: %v (status %d)", err, exitErr.ExitCode())
				} else {
					t.Errorf("unexpected wait error: %v", err)
				}
			}
		case <-time.After(10 * time.Second):
			t.Error("server did not exit within 10s after SIGTERM")
			serverCmd.Process.Kill()
		}
	})
}

// shortTempDir creates a temp directory with a short path to avoid
// hitting the ~104 byte Unix socket path limit on macOS.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "es")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// availablePort returns an ephemeral TCP port that is currently available.
func availablePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// waitForTCP polls until a TCP address accepts connections.
func waitForTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to accept connections", addr)
}
