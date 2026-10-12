package server_test

import (
	"bytes"
	"context"
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

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/test/oidctest"
)

// TestServerEndToEnd verifies the combined server starts a router and four
// private services, routes requests, and cleans up the supervised processes.
func TestServerEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Real in-process IdP: serves discovery, JWKS, and can mint real signed
	// ID tokens, so this test (and any future addition to it) exercises the
	// actual token-validation path rather than a stub that never verifies
	// anything.
	idp := oidctest.New(t)
	idp.SetDiscoveryAvailable(false)
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

	// User configuration and managed host storage are independent.
	policyPath := filepath.Join(tmpDir, "policy.writ")
	if err := os.WriteFile(policyPath, []byte("allow user{name:\"test@example.com\"} -> root@*\n"), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}
	seedManagedPattern(t, filepath.Join(tmpDir, "state"), nil)
	directoryPath := filepath.Join(tmpDir, "directory.yaml")
	if err := os.WriteFile(directoryPath, []byte("users:\n  - userName: test@example.com\n    id: subject:test@example.com\n"), 0644); err != nil {
		t.Fatalf("failed to write directory: %v", err)
	}

	// Flat TOML keys use the long flag names verbatim.
	configPath := filepath.Join(tmpDir, "config.toml")
	controlPath := writeControlKey(t, tmpDir)
	configContent := fmt.Sprintf(`ca-key-file = %q
control-key-file = %q
policy-file = %q
oidc-issuer = %q
oidc-client-id = %q
state-dir = %q
`, caKeyPath, controlPath, policyPath, mockURL, oidctest.ClientID, filepath.Join(tmpDir, "state"))

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
		"--directory-static-file", directoryPath,
		"-v",
	)
	runtimeDir := filepath.Join(tmpDir, "run")
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	serverCmd.Env = append(os.Environ(), "TMPDIR="+runtimeDir)
	serverCmd.Stdout = os.Stderr
	serverCmd.Stderr = os.Stderr

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Wait for the server to accept TCP connections.
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	waitForTCP(t, fmt.Sprintf("localhost:%d", port), 15*time.Second)

	client := &http.Client{Timeout: 3 * time.Second}
	checkStatus := func(t *testing.T, path string, want int) string {
		t.Helper()
		resp, err := client.Get(baseURL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("GET %s: status %d, want %d: %s", path, resp.StatusCode, want, body)
		}
		return string(body)
	}
	requestCert := func(t *testing.T, token string, want int) {
		t.Helper()
		key, _, err := sshcert.GenerateKeys()
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(wire.CreateCertRequest{PublicKey: key, Connection: wire.Connection{RemoteHost: "host", RemoteUser: "root"}})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("POST", baseURL+"/", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		response, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("issuance: status %d, want %d: %s", resp.StatusCode, want, response)
		}
		if want == http.StatusOK {
			var certResponse wire.CreateCertResponse
			if err := json.Unmarshal(response, &certResponse); err != nil {
				t.Fatal(err)
			}
			cert, err := sshcert.Parse(certResponse.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			if cert.KeyId != "test@example.com" || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "root" {
				t.Fatalf("unexpected certificate: identity %q, principals %v", cert.KeyId, cert.ValidPrincipals)
			}
		}
	}
	t.Run("startup_recovers_after_provider_outage", func(t *testing.T) {
		// Keep the external dependency down beyond the supervisor's ten-second
		// socket deadline. The same process must remain alive and explain why
		// it is unready, while bootstrap continues to work.
		deadline := time.Now().Add(11 * time.Second)
		for time.Now().Before(deadline) {
			checkStatus(t, "/", http.StatusOK)
			reason := checkStatus(t, "/readyz", http.StatusServiceUnavailable)
			if !strings.Contains(reason, "OIDC discovery unavailable") {
				t.Fatalf("missing readiness reason: %s", reason)
			}
			time.Sleep(100 * time.Millisecond)
		}
		checkStatus(t, "/", http.StatusOK)
		checkStatus(t, "/discovery", http.StatusOK)
		token := idp.MintIDToken("test@example.com", time.Now().Add(time.Minute))
		requestCert(t, token, http.StatusBadGateway)
		req, err := http.NewRequest("POST", baseURL+"/inventory", strings.NewReader(`{"action":"list"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("control during discovery: status %d", resp.StatusCode)
		}
		idp.SetDiscoveryAvailable(true)
		deadline = time.Now().Add(35 * time.Second)
		for {
			resp, err := client.Get(baseURL + "/readyz")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("server did not recover after provider restoration")
			}
			time.Sleep(100 * time.Millisecond)
		}
		requestCert(t, token, http.StatusOK)
		requestCert(t, "invalid-token", http.StatusUnauthorized)
		idp.SetDiscoveryAvailable(false)
		checkStatus(t, "/readyz", http.StatusOK)
		requestCert(t, token, http.StatusOK)
		idp.SetDiscoveryAvailable(true)
	})

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

	t.Run("router_bind_failure_cleans_up", func(t *testing.T) {
		// The public port belongs to the last-started child. If it cannot bind,
		// the supervisor must stop the already-running private services too.
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		failed := exec.CommandContext(ctx, epithetBin, "--config", configPath, "server",
			"--listen", occupied.Addr().String(),
			"--directory-static-file", directoryPath)
		failed.Env = serverCmd.Env
		output, err := failed.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("supervisor did not exit after router failure: %s", output)
		}
		if err == nil || !strings.Contains(string(output), "router subprocess exited") {
			t.Fatalf("expected router startup failure, got %v: %s", err, output)
		}
		entries, err := os.ReadDir(runtimeDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("private sockets remain after shutdown/failure: %v", entries)
		}
	})

	t.Run("shutdown_during_discovery_cleans_up", func(t *testing.T) {
		idp.SetDiscoveryAvailable(false)
		port := availablePort(t)
		pending := exec.CommandContext(t.Context(), epithetBin, "--config", configPath, "server",
			"--listen", fmt.Sprintf("127.0.0.1:%d", port), "--directory-static-file", directoryPath)
		pending.Env = serverCmd.Env
		pending.Stderr = os.Stderr
		if err := pending.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- pending.Wait() }()
		t.Cleanup(func() { pending.Process.Kill() })
		waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
		if err := pending.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("shutdown during discovery: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("shutdown remained blocked by discovery")
		}
		entries, err := os.ReadDir(runtimeDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("private sockets remain after shutdown: %v", entries)
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

func writeControlKey(t *testing.T, dir string) string {
	t.Helper()
	_, key, err := sshcert.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.key")
	if err := os.WriteFile(path, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedManagedPattern(t *testing.T, state string, accounts []string) {
	t.Helper()
	store, err := inventorysqlite.Open(filepath.Join(state, "inventory", "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record, err := store.Enroll(t.Context(), inventory.Proposal{Pattern: "*", Accounts: accounts, PrincipalMode: inventory.AccountNamePrincipals}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Change(t.Context(), "admin", "approve", record.ID, record.Revision, nil); err != nil {
		t.Fatal(err)
	}
}
