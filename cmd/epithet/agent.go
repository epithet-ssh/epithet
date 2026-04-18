package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// AgentCLI is the parent command for agent-related subcommands.
// Shared flags (CaURL, Auth) are defined here and inherited by subcommands.
type AgentCLI struct {
	CaURL      []string      `help:"CA URL (repeatable, format: priority=N:https://url or https://url)" name:"ca-url" short:"c"`
	Auth       string        `help:"Authentication command (optional if CA provides bootstrap discovery)" short:"a"`
	CaTimeout  time.Duration `help:"Per-request timeout for CA requests" name:"ca-timeout" default:"15s"`
	CaCooldown time.Duration `help:"Circuit breaker cooldown for failed CAs" name:"ca-cooldown" default:"10m"`

	Start   AgentStartCLI   `cmd:"" default:"withargs" help:"Start the epithet agent"`
	Inspect AgentInspectCLI `cmd:"inspect" help:"Inspect broker state (certificates, agents)"`
}

// AgentStartCLI is the default subcommand that starts the agent/broker.
// When Shell is provided, it runs in wrapper mode: wrapping a shell with an
// epithet-aware agent proxy (mirroring ssh-agent's "ssh-agent bash" pattern).
type AgentStartCLI struct {
	Shell string `arg:"" optional:"" help:"Shell to wrap with epithet agent (enables wrapper mode)"`
}

func (s *AgentStartCLI) Run(parent *AgentCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	if s.Shell != "" {
		return s.runWrapper(parent, logger, tlsCfg)
	}
	return s.runDaemon(parent, logger, tlsCfg)
}

// runDaemon runs the broker as a long-lived daemon (original behavior).
func (s *AgentStartCLI) runDaemon(parent *AgentCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	b, tempDir, brokerSock, agentDir, homeDir, err := setupBrokerWithOptions(parent, logger, tlsCfg, false)
	if err != nil {
		return err
	}

	// Clean up temp directory on exit.
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			logger.Warn("failed to remove temp directory", "error", err, "path", tempDir)
		} else {
			logger.Debug("removed temp directory", "path", tempDir)
		}
	}()

	// Set up context with cancellation on signals.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("received shutdown signal")
		cancel()
	}()

	// Generate SSH config.
	sshConfigPath := filepath.Join(tempDir, "ssh-config.conf")
	if err := parent.generateSSHConfig(sshConfigPath, agentDir, brokerSock, homeDir); err != nil {
		logger.Warn("failed to generate SSH config", "error", err, "path", sshConfigPath)
	} else {
		includePattern := filepath.Join(homeDir, ".epithet", "run", "*", "ssh-config.conf")
		if err := checkSSHConfigInclude(homeDir, includePattern, logger); err != nil {
			logger.Warn(fmt.Sprintf("Add 'Include %s' to ~/.ssh/config", includePattern))
		}
		logger.Debug("generated SSH config", "path", sshConfigPath)
	}

	// Start broker.
	logger.Info("starting broker", "socket", brokerSock)
	err = b.Serve(ctx)
	if err != nil && err != context.Canceled {
		return fmt.Errorf("broker serve error: %w", err)
	}

	logger.Info("broker shutdown complete")
	return nil
}

// runWrapper wraps a shell with an epithet-aware agent proxy. It probes the
// current SSH_AUTH_SOCK for an upstream epithet agent, starts the broker, and
// creates a proxy listener that handles epithet protocol extensions while
// delegating standard SSH agent operations to the upstream agent.
func (s *AgentStartCLI) runWrapper(parent *AgentCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	upstreamSocket := os.Getenv("SSH_AUTH_SOCK")

	// Probe for upstream epithet agent.
	var depth int
	var brokerOpts []broker.Option
	if upstreamSocket != "" {
		hello, err := agent.ProbeUpstream(upstreamSocket)
		if err != nil {
			logger.Warn("failed to probe upstream agent", "error", err)
		} else if hello != nil {
			depth = hello.ChainDepth + 1
			brokerOpts = append(brokerOpts, broker.WithUpstream(upstreamSocket))
			logger.Info("detected upstream epithet agent", "chain_depth", depth)
		} else {
			logger.Debug("upstream is vanilla ssh-agent")
		}
	} else {
		logger.Debug("no SSH_AUTH_SOCK set")
	}

	b, tempDir, brokerSock, agentDir, homeDir, err := setupBrokerWithOptions(parent, logger, tlsCfg, true, brokerOpts...)
	if err != nil {
		return err
	}

	// Clean up temp directory on exit.
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			logger.Warn("failed to remove temp directory", "error", err, "path", tempDir)
		}
	}()

	// Set up context with cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start broker in background.
	brokerErr := make(chan error, 1)
	go func() {
		brokerErr <- b.Serve(ctx)
	}()
	<-b.Ready()

	// Generate SSH config.
	sshConfigPath := filepath.Join(tempDir, "ssh-config.conf")
	if err := parent.generateSSHConfig(sshConfigPath, agentDir, brokerSock, homeDir); err != nil {
		logger.Warn("failed to generate SSH config", "error", err, "path", sshConfigPath)
	} else {
		includePattern := filepath.Join(homeDir, ".epithet", "run", "*", "ssh-config.conf")
		if err := checkSSHConfigInclude(homeDir, includePattern, logger); err != nil {
			logger.Warn(fmt.Sprintf("Add 'Include %s' to ~/.ssh/config", includePattern))
		}
	}

	// Create proxy listener if we have an upstream socket to proxy.
	if upstreamSocket != "" {
		proxySock := filepath.Join(tempDir, "proxy.sock")
		setup := func(p *agent.ProxyAgent) {
			p.RegisterExtension(agent.ExtensionHello, agent.HelloHandler(depth))
			p.RegisterExtension(agent.ExtensionAuth, agent.AuthHandler(func() (string, error) {
				return b.Authenticate(nil)
			}))
		}
		proxyListener := agent.NewProxyListener(logger, proxySock, upstreamSocket, setup)
		go func() {
			if err := proxyListener.Serve(ctx); err != nil && err != context.Canceled {
				logger.Error("proxy listener error", "error", err)
			}
		}()
		<-proxyListener.Ready()
		upstreamSocket = proxySock
		logger.Info("proxy agent listening", "socket", proxySock)
	}

	// Build child environment with updated SSH_AUTH_SOCK.
	childEnv := os.Environ()
	if upstreamSocket != "" {
		childEnv = replaceEnv(childEnv, "SSH_AUTH_SOCK", upstreamSocket)
	}

	// Run the shell as a child process.
	cmd := exec.Command(s.Shell)
	cmd.Env = childEnv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Forward signals to child.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				cmd.Process.Signal(sig)
			}
		}
	}()

	logger.Info("starting shell", "shell", s.Shell)
	shellErr := cmd.Run()

	// Shell exited — shut down broker and drain its error.
	cancel()
	signal.Stop(sigChan)
	if err := <-brokerErr; err != nil && err != context.Canceled {
		logger.Error("broker error", "error", err)
	}

	if shellErr != nil {
		var exitErr *exec.ExitError
		if errors.As(shellErr, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("shell failed: %w", shellErr)
	}

	return nil
}

// setupBrokerWithOptions creates the broker, temp directories, and resolves auth.
// When wrapperMode is true, uses a per-process temp directory to avoid collisions
// between multiple wrapped shells. When false (daemon mode), uses a deterministic
// path derived from the CA URLs so SSH config includes can find it.
// Returns (broker, tempDir, brokerSock, agentDir, homeDir, error).
func setupBrokerWithOptions(parent *AgentCLI, logger *slog.Logger, tlsCfg tlsconfig.Config, wrapperMode bool, opts ...broker.Option) (*broker.Broker, string, string, string, string, error) {
	if len(parent.CaURL) == 0 {
		return nil, "", "", "", "", fmt.Errorf("--ca-url is required (at least one)")
	}

	caEndpoints, err := caclient.ParseCAURLs(parent.CaURL)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("invalid CA URL: %w", err)
	}

	logger.Debug("agent command received", "ca_urls", parent.CaURL, "ca_timeout", parent.CaTimeout, "ca_cooldown", parent.CaCooldown)

	for _, ep := range caEndpoints {
		if err := tlsCfg.ValidateURL(ep.URL); err != nil {
			return nil, "", "", "", "", fmt.Errorf("CA URL %q: %w", ep.URL, err)
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to get home directory: %w", err)
	}

	runDir := filepath.Join(homeDir, ".epithet", "run")
	cleanupStaleRunDirs(runDir, logger)

	var tempDir string
	if wrapperMode {
		// Wrapper mode: each invocation gets its own directory to avoid
		// collisions between multiple wrapped shells against the same CA.
		tempDir, err = os.MkdirTemp(runDir, "wrap-")
		if err != nil {
			// Ensure runDir exists and retry.
			if mkErr := os.MkdirAll(runDir, 0700); mkErr != nil {
				return nil, "", "", "", "", fmt.Errorf("failed to create run directory: %w", mkErr)
			}
			tempDir, err = os.MkdirTemp(runDir, "wrap-")
			if err != nil {
				return nil, "", "", "", "", fmt.Errorf("failed to create temp directory: %w", err)
			}
		}
	} else {
		// Daemon mode: deterministic path so SSH config includes can find it.
		instanceID := hashString(fmt.Sprintf("%v", parent.CaURL))
		tempDir = filepath.Join(runDir, instanceID)
		if err := os.MkdirAll(tempDir, 0700); err != nil {
			return nil, "", "", "", "", fmt.Errorf("failed to create temp directory: %w", err)
		}
	}

	pidFile := filepath.Join(tempDir, "broker.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to write PID file: %w", err)
	}

	brokerSock := filepath.Join(tempDir, "broker.sock")
	agentDir := filepath.Join(tempDir, "agent")

	if err := os.MkdirAll(agentDir, 0700); err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to create agent directory: %w", err)
	}

	caClientOpts := []caclient.Option{
		caclient.WithLogger(logger),
		caclient.WithTimeout(parent.CaTimeout),
		caclient.WithCooldown(parent.CaCooldown),
		caclient.WithTLSConfig(tlsCfg),
	}
	caClient, err := caclient.New(caEndpoints, caClientOpts...)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to create CA client: %w", err)
	}

	authCommand := parent.Auth
	if authCommand == "" {
		logger.Debug("no --auth provided, discovering from CA")

		_, err := caClient.GetPublicKey(context.Background())
		if err != nil {
			return nil, "", "", "", "", fmt.Errorf("failed to get CA public key: %w", err)
		}

		discovery, err := caClient.GetDiscovery(context.Background(), "")
		if err != nil {
			return nil, "", "", "", "", fmt.Errorf("failed to get discovery config (try --auth to specify manually): %w", err)
		}
		if discovery == nil || discovery.Auth == nil {
			return nil, "", "", "", "", fmt.Errorf("CA did not return auth config in discovery (try --auth to specify manually)")
		}

		authCommand, err = broker.AuthConfigToCommand(*discovery.Auth)
		if err != nil {
			return nil, "", "", "", "", fmt.Errorf("failed to convert discovery auth config: %w", err)
		}

		logger.Info("discovered auth config from CA", "type", discovery.Auth.Type, "issuer", discovery.Auth.Issuer)
	}

	b, err := broker.New(*logger, brokerSock, authCommand, caClient, agentDir, opts...)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to create broker: %w", err)
	}

	return b, tempDir, brokerSock, agentDir, homeDir, nil
}

// replaceEnv returns a copy of environ with key set to value.
// If key already exists, it is replaced; otherwise it is appended.
func replaceEnv(environ []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environ)+1)
	found := false
	for _, e := range environ {
		if strings.HasPrefix(e, prefix) {
			result = append(result, prefix+value)
			found = true
		} else {
			result = append(result, e)
		}
	}
	if !found {
		result = append(result, prefix+value)
	}
	return result
}

// generateSSHConfig writes an SSH config file for epithet
func (a *AgentCLI) generateSSHConfig(path, agentDir, brokerSock, homeDir string) error {
	// Find epithet binary path
	epithetPath, err := os.Executable()
	if err != nil {
		epithetPath = "epithet" // fallback to PATH
	}

	// Generate include path with full home directory (SSH doesn't expand ~)
	includePattern := filepath.Join(homeDir, ".epithet", "run", "*", "ssh-config.conf")

	// SSH config uses Match exec only - the broker checks discovery patterns dynamically.
	// We only set IdentityAgent to point to the per-connection agent. This allows normal
	// fallback to ~/.ssh/id_* keys and password auth if epithet certificates aren't available,
	// which is important for production failure recovery.
	config := fmt.Sprintf(`# Generated by epithet agent - do not edit manually
# This file is automatically created when the broker starts and deleted when it stops
# Broker socket: %s
# Agent directory: %s
#
# To use epithet, add the following to ~/.ssh/config:
#   Include %s

Match exec "%s match --host '%%h' --port '%%p' --user '%%r' --jump '%%j' --hash '%%C' --broker '%s'"
    IdentityAgent %s/%%C
`,
		brokerSock,
		agentDir,
		includePattern,
		epithetPath,
		brokerSock,
		agentDir,
	)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write config file
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write SSH config: %w", err)
	}

	return nil
}

// checkSSHConfigInclude checks if ~/.ssh/config contains the Include directive for epithet
func checkSSHConfigInclude(homeDir, includePattern string, logger *slog.Logger) error {
	sshConfigPath := filepath.Join(homeDir, ".ssh", "config")

	// Read SSH config file
	content, err := os.ReadFile(sshConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debug("~/.ssh/config does not exist", "path", sshConfigPath)
			return fmt.Errorf("SSH config not found")
		}
		return fmt.Errorf("failed to read SSH config: %w", err)
	}

	// Check for Include directive (case-insensitive, flexible whitespace)
	lines := strings.SplitSeq(string(content), "\n")
	for line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Check for Include directive (case-insensitive)
		if strings.HasPrefix(strings.ToLower(trimmed), "include ") {
			// Extract the path after "Include"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				includePath := parts[1]
				// Expand ~ if present
				if strings.HasPrefix(includePath, "~/") {
					includePath = filepath.Join(homeDir, includePath[2:])
				}
				// Check if it matches our pattern
				if includePath == includePattern {
					logger.Debug("found epithet Include directive in ~/.ssh/config")
					return nil
				}
			}
		}
	}

	return fmt.Errorf("Include directive not found")
}

// hashString creates a short hash of a string for use in filenames
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8]) // Use first 8 bytes (16 hex chars)
}

// cleanupStaleRunDirs removes run directories from dead processes
func cleanupStaleRunDirs(runDir string, logger *slog.Logger) {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		if os.IsNotExist(err) {
			return // No run directory yet, nothing to clean
		}
		logger.Warn("failed to read run directory", "error", err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		instanceDir := filepath.Join(runDir, entry.Name())
		pidFile := filepath.Join(instanceDir, "broker.pid")

		pidBytes, err := os.ReadFile(pidFile)
		if err != nil {
			// No PID file - could be old format or corrupted, remove it
			logger.Info("removing run directory without PID file", "path", instanceDir)
			if err := os.RemoveAll(instanceDir); err != nil {
				logger.Warn("failed to remove stale directory", "path", instanceDir, "error", err)
			}
			continue
		}

		pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if err != nil {
			logger.Warn("invalid PID file", "path", pidFile, "error", err)
			if err := os.RemoveAll(instanceDir); err != nil {
				logger.Warn("failed to remove stale directory", "path", instanceDir, "error", err)
			}
			continue
		}

		// Check if process is alive
		process, err := os.FindProcess(pid)
		if err != nil {
			// On Unix, FindProcess always succeeds, but let's be safe
			if err := os.RemoveAll(instanceDir); err != nil {
				logger.Warn("failed to remove stale directory", "path", instanceDir, "error", err)
			}
			continue
		}

		// Send signal 0 to check if process exists
		err = process.Signal(syscall.Signal(0))
		if err != nil {
			// Process is dead
			logger.Info("removing stale run directory", "path", instanceDir, "dead_pid", pid)
			if err := os.RemoveAll(instanceDir); err != nil {
				logger.Warn("failed to remove stale directory", "path", instanceDir, "error", err)
			}
		}
	}
}
