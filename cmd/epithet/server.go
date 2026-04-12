package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"golang.org/x/crypto/ssh"
)

// ServerCLI defines the CLI flags for the combined server command.
// It runs both the CA and policy server as subprocesses, with the CA
// listening on the public port. The CA handles all client traffic
// (including /discovery) and communicates with the policy server
// internally via a Unix domain socket.
type ServerCLI struct {
	Listen string `help:"Public address to listen on" short:"l" default:":8080"`
	CAKey  string `help:"Path to CA private key" name:"ca-key" default:"/etc/epithet/ca.key"`
}

func (c *ServerCLI) Run(logger *slog.Logger, _ tlsconfig.Config) error {
	caKeyPath := c.CAKey

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

	// Create temp directory for the policy domain socket.
	tmpDir, err := os.MkdirTemp("", "epithet-server-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	policySock := filepath.Join(tmpDir, "policy.sock")

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

	// Start CA subprocess — listens directly on the public port.
	// The CA handles all client traffic including /discovery.
	caArgs := append(globalArgs, "ca",
		"--listen", c.Listen,
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
	logger.Info("started ca subprocess", "pid", caCmd.Process.Pid, "listen", c.Listen)

	// Wait for either subprocess to exit or signal.
	// The goroutines call Wait() which reaps the process, so we must not
	// call Wait() again in the shutdown path.
	errCh := make(chan error, 2)
	go func() { errCh <- caCmd.Wait() }()
	go func() { errCh <- policyCmd.Wait() }()

	var subprocessErr error
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case subprocessErr = <-errCh:
		cancel()
		if subprocessErr != nil {
			logger.Error("subprocess exited with error", "error", subprocessErr)
		}
	}

	// Graceful shutdown: signal both subprocesses. The goroutines above
	// will reap them via Wait(). Drain the channel to avoid leaking goroutines.
	_ = caCmd.Process.Signal(syscall.SIGTERM)
	_ = policyCmd.Process.Signal(syscall.SIGTERM)
	<-errCh // Wait for the second subprocess goroutine to finish.

	logger.Info("shutdown complete")
	return subprocessErr
}

// buildGlobalArgs constructs the global CLI flags to pass through to subprocesses.
func buildGlobalArgs() []string {
	var args []string
	if cli.Config != "" {
		args = append(args, "--config", string(cli.Config))
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
