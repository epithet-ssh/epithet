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
	"sync"
	"syscall"
	"time"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"golang.org/x/crypto/ssh"
)

// ServerCLI defines the CLI flags for the combined server command.
// It supervises CA, policy, and inventory subprocesses. Only the CA listens
// on the public port; it contacts both private services over Unix sockets.
type ServerCLI struct {
	Listen string `help:"Public address to listen on" short:"l" default:":8080"`
	CAKey  string `help:"Path to CA private key" name:"ca-key" default:"/etc/epithet/ca.key"`

	// Policy flags threaded through to the policy subprocess. The
	// subprocess re-runs Kong against the same --config, so these are
	// only needed when configuring via flags rather than a config file.
	PolicyFile string            `help:"Path to the writ policy file" name:"policy-file"`
	Inventory  []string          `help:"Inventory file path or glob (repeatable)" name:"inventory"`
	Extension  map[string]string `help:"Certificate extension for issued certs (name=value, repeatable)" name:"extension"`
	// Leave unset to inherit inventory configuration (including its default).
	// Validate in Run so Kong does not require an enum default here.
	PrincipalMode string `help:"Override inventory principal mode: account-name or epithet-principal-v1 (default: inherit inventory configuration)" name:"principal-mode"`
}

func (c *ServerCLI) Run(logger *slog.Logger, _ tlsconfig.Config) error {
	if err := inventory.PrincipalMode(c.PrincipalMode).Validate(); err != nil {
		return err
	}
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

	inventorySock := filepath.Join(tmpDir, "inventory.sock")
	type child struct {
		name   string
		args   []string
		socket string
	}
	children := []child{
		{"inventory", c.inventoryArgs(globalArgs, inventorySock, caPubkey), inventorySock},
		{"policy", c.policyArgs(globalArgs, policySock, caPubkey), policySock},
		{"ca", append(append([]string{}, globalArgs...), "ca", "--listen", c.Listen, "--policy", "unix://"+policySock, "--inventory", "unix://"+inventorySock, "--key", caKeyPath), ""},
	}
	var wg sync.WaitGroup
	exited := make(chan error, len(children))
	// Every started child is reaped, including startup failures and signals.
	defer func() { cancel(); wg.Wait() }()
	for _, child := range children {
		cmd := exec.CommandContext(ctx, os.Args[0], child.args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("starting %s: %w", child.name, err)
		}
		logger.Info("started subprocess", "service", child.name, "pid", cmd.Process.Pid)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cmd.Wait()
			exited <- fmt.Errorf("%s subprocess exited: %v", child.name, err)
		}()
		if child.socket != "" {
			ready := make(chan error, 1)
			go func() { ready <- waitForSocket(ctx, child.socket, 10*time.Second) }()
			select {
			case err := <-ready:
				if err != nil {
					return err
				}
			case err := <-exited:
				return err
			case <-ctx.Done():
				return nil
			}
		}
	}
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		return nil
	case err := <-exited:
		return err
	}
}

func (c *ServerCLI) inventoryArgs(globalArgs []string, socket, key string) []string {
	args := append(append([]string{}, globalArgs...), "inventory", "--listen", "unix://"+socket, "--ca-pubkey", key)
	for _, path := range c.Inventory {
		args = append(args, "--static", path)
	}
	if c.PrincipalMode != "" {
		args = append(args, "--principal-mode", c.PrincipalMode)
	}
	return args
}

// policyArgs builds the subprocess command. Only explicit server overrides
// should be forwarded; the policy subprocess reads its own configuration.
func (c *ServerCLI) policyArgs(globalArgs []string, policySock, caPubkey string) []string {
	policyArgs := append(append([]string{}, globalArgs...), "policy",
		"--listen", "unix://"+policySock,
		"--ca-pubkey", caPubkey,
	)
	if c.PolicyFile != "" {
		policyArgs = append(policyArgs, "--policy-file", c.PolicyFile)
	}
	for name, value := range c.Extension {
		policyArgs = append(policyArgs, "--extension", name+"="+value)
	}
	return policyArgs
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
