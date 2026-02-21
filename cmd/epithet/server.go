package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"cuelang.org/go/cue"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"golang.org/x/crypto/ssh"
)

// ServerCLI defines the CLI flags for the combined server command.
// It runs both the CA and policy server as subprocesses behind a
// single reverse proxy, simplifying deployment to a single process.
type ServerCLI struct {
	Listen string `help:"Public address to listen on" short:"l" default:":8080"`
}

func (c *ServerCLI) Run(logger *slog.Logger, _ tlsconfig.Config, unifiedConfig cue.Value) error {
	// Read CA key path from ca.key in config, falling back to default.
	caKeyPath := "/etc/epithet/ca.key"
	if v := unifiedConfig.LookupPath(cue.ParsePath("ca.key")); v.Exists() {
		if err := v.Decode(&caKeyPath); err != nil {
			return fmt.Errorf("failed to decode ca.key from config: %w", err)
		}
	}

	// Read CA private key and derive the public key so the policy
	// server doesn't need separate configuration for it.
	privKeyBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("unable to load ca key from %s: %w", caKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to parse ca key: %w", err)
	}
	caPubkey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	logger.Info("derived ca public key", "path", caKeyPath)

	// Create temp directory for domain sockets.
	tmpDir, err := os.MkdirTemp("", "epithet-server-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	policySock := filepath.Join(tmpDir, "policy.sock")
	caSock := filepath.Join(tmpDir, "ca.sock")

	// Set up signal-aware context for subprocess lifecycle.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Build global flags to pass through to subprocesses.
	globalArgs := buildGlobalArgs()

	// Start policy subprocess first — the CA depends on it.
	policyArgs := append(globalArgs, "policy",
		"--listen", "unix://"+policySock,
		"--ca-pubkey", caPubkey,
	)
	policyCmd := exec.CommandContext(ctx, os.Args[0], policyArgs...)
	policyCmd.Stdout = os.Stdout
	policyCmd.Stderr = os.Stderr
	if err := policyCmd.Start(); err != nil {
		return fmt.Errorf("failed to start policy subprocess: %w", err)
	}
	logger.Info("started policy subprocess", "pid", policyCmd.Process.Pid, "socket", policySock)

	if err := waitForSocket(ctx, policySock, 10*time.Second); err != nil {
		_ = policyCmd.Process.Kill()
		return fmt.Errorf("policy subprocess failed to become ready: %w", err)
	}
	logger.Info("policy subprocess ready")

	// Start CA subprocess.
	caArgs := append(globalArgs, "ca",
		"--listen", "unix://"+caSock,
		"--policy", "unix://"+policySock,
		"--key", caKeyPath,
	)
	caCmd := exec.CommandContext(ctx, os.Args[0], caArgs...)
	caCmd.Stdout = os.Stdout
	caCmd.Stderr = os.Stderr
	if err := caCmd.Start(); err != nil {
		_ = policyCmd.Process.Kill()
		return fmt.Errorf("failed to start ca subprocess: %w", err)
	}
	logger.Info("started ca subprocess", "pid", caCmd.Process.Pid, "socket", caSock)

	if err := waitForSocket(ctx, caSock, 10*time.Second); err != nil {
		_ = caCmd.Process.Kill()
		_ = policyCmd.Process.Kill()
		return fmt.Errorf("ca subprocess failed to become ready: %w", err)
	}
	logger.Info("ca subprocess ready")

	// Build reverse proxy mux. /d/* routes to policy, everything else to CA.
	mux := http.NewServeMux()
	mux.Handle("/d/", unixReverseProxy(policySock, logger))
	mux.Handle("/", unixReverseProxy(caSock, logger))

	logger.Info("listening", "address", c.Listen)
	server := &http.Server{
		Addr:    c.Listen,
		Handler: mux,
	}

	// Run HTTP server in a goroutine so we can handle shutdown.
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	// Wait for either context cancellation (signal) or server error.
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errCh:
		cancel()
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http server error: %w", err)
		}
	}

	// Graceful shutdown: stop accepting connections, then stop subprocesses.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	// Stop CA first (stop accepting cert requests), then policy.
	_ = caCmd.Process.Signal(syscall.SIGTERM)
	_ = caCmd.Wait()
	_ = policyCmd.Process.Signal(syscall.SIGTERM)
	_ = policyCmd.Wait()

	logger.Info("shutdown complete")
	return nil
}

// buildGlobalArgs constructs the global CLI flags to pass through to subprocesses.
func buildGlobalArgs() []string {
	var args []string
	if configFlag := strings.Join([]string(cli.Config), ";"); configFlag != "" {
		args = append(args, "--config", configFlag)
	}
	for i := 0; i < cli.Verbose; i++ {
		args = append(args, "-v")
	}
	if cli.Insecure {
		args = append(args, "--insecure")
	}
	if cli.TLSCACert != "" {
		args = append(args, "--tls-ca-cert", cli.TLSCACert)
	}
	if cli.LogFile != "" {
		args = append(args, "--log-file", cli.LogFile)
	}
	return args
}

// unixReverseProxy creates an httputil.ReverseProxy that routes to a Unix domain socket.
func unixReverseProxy(socketPath string, logger *slog.Logger) http.Handler {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "localhost"
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("proxy error", "path", r.URL.Path, "error", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return proxy
}

// waitForSocket polls until a Unix domain socket accepts connections or the context is cancelled.
func waitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timed out waiting for socket %s", path)
		case <-ticker.C:
			conn, err := net.DialTimeout("unix", path, time.Second)
			if err == nil {
				conn.Close()
				return nil
			}
		}
	}
}
