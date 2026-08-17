package server_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// TestServerEndToEnd verifies the combined server command starts CA and policy
// subprocesses and routes requests correctly through the reverse proxy.
func TestServerEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Real in-process IdP: serves discovery, JWKS, and can mint real signed
	// ID tokens, so this test (and any future addition to it) exercises the
	// actual token-validation path rather than a stub that never verifies
	// anything.
	idp := oidctest.New(t)
	mockURL := idp.Issuer()

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
	configContent := fmt.Sprintf(`server:
  ca-key: %s
policy:
  ca-pubkey: "%s"
  oidc:
    issuer: "%s"
    client-id: "%s"
  users:
    test@example.com: [admin]
  defaults:
    allow:
      root: [admin]
    expiration: "5m"
`, caKeyPath, strings.TrimSpace(string(caPubkey)), mockURL, oidctest.ClientID)

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

	// GET /discovery (no auth) → 200 with auth config. Discovery is a
	// plain anonymous pass-through now (Task 8): no Vary header, since
	// there's no authenticated variant to distinguish from.
	t.Run("discovery_unauth", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/discovery")
		if err != nil {
			t.Fatalf("GET /discovery failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("GET /discovery status = %d, want 200", resp.StatusCode)
		}

		if vary := resp.Header.Get("Vary"); vary != "" {
			t.Errorf("Vary = %q, want empty", vary)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read discovery body: %v", err)
		}
		var d wire.Discovery
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatalf("failed to parse discovery body: %v", err)
		}
		if d.Auth == nil || d.Auth.Issuer == "" || d.Auth.ClientID == "" {
			t.Errorf("discovery auth config incomplete: %+v", d.Auth)
		}
	})

	// GET / advertises discovery via a relative Link target, and following it
	// reaches the same document. This crosses the combined server's reverse
	// proxy, which must not strip the header.
	t.Run("discovery_via_link", func(t *testing.T) {
		resp, err := http.Get(baseURL)
		if err != nil {
			t.Fatalf("GET / failed: %v", err)
		}
		defer resp.Body.Close()

		link := resp.Header.Get("Link")
		if !strings.Contains(link, "https://epithet.dev/rel/auth") {
			t.Fatalf("Link = %q, want it to advertise the auth relation", link)
		}

		base, err := url.Parse(baseURL)
		if err != nil {
			t.Fatalf("bad baseURL: %v", err)
		}
		if !strings.HasSuffix(base.Path, "/") {
			base.Path += "/"
		}
		ref, err := url.Parse("discovery")
		if err != nil {
			t.Fatalf("bad reference: %v", err)
		}
		target := base.ResolveReference(ref)

		dresp, err := http.Get(target.String())
		if err != nil {
			t.Fatalf("GET %s failed: %v", target, err)
		}
		defer dresp.Body.Close()

		if dresp.StatusCode != 200 {
			t.Fatalf("GET %s status = %d, want 200", target, dresp.StatusCode)
		}

		var d wire.Discovery
		if err := json.NewDecoder(dresp.Body).Decode(&d); err != nil {
			t.Fatalf("failed to decode discovery: %v", err)
		}
		if d.Auth == nil || d.Auth.Issuer == "" {
			t.Errorf("discovery auth = %+v, want a populated issuer", d.Auth)
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
