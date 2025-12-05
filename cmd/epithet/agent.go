package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// AgentCLI is the parent command for agent-related subcommands.
// Shared flags (Match, CaURL, Auth) are defined here and inherited by subcommands.
type AgentCLI struct {
	Match []string `help:"Match patterns" short:"m"`
	CaURL string   `help:"CA URL" name:"ca-url" short:"c"`
	Auth  string   `help:"Authentication command" short:"a"`

	Start   AgentStartCLI   `cmd:"" default:"withargs" help:"Start the epithet agent"`
	Inspect AgentInspectCLI `cmd:"inspect" help:"Inspect broker state (certificates, agents)"`
}

// AgentStartCLI is the default subcommand that starts the agent/broker.
type AgentStartCLI struct{}

func (s *AgentStartCLI) Run(parent *AgentCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	// Validate required fields for start
	if parent.CaURL == "" {
		return fmt.Errorf("--ca-url is required")
	}
	if parent.Auth == "" {
		return fmt.Errorf("--auth is required")
	}

	logger.Debug("agent start command received", "ca_url", parent.CaURL, "match", parent.Match)

	// Validate CA URL requires TLS (unless --insecure)
	if err := tlsCfg.ValidateURL(parent.CaURL); err != nil {
		return err
	}

	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// Create a unique temporary directory for this broker instance
	// Use a hash of the CA URL + match patterns to make it deterministic
	instanceID := hashString(parent.CaURL + fmt.Sprintf("%v", parent.Match))
	runDir := filepath.Join(homeDir, ".epithet", "run")
	tempDir := filepath.Join(runDir, instanceID)

	// Clean up stale run directories from dead processes
	cleanupStaleRunDirs(runDir, logger)

	// Clean up temp directory on exit
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			logger.Warn("failed to remove temp directory", "error", err, "path", tempDir)
		} else {
			logger.Debug("removed temp directory", "path", tempDir)
		}
	}()

	// Create temp directory
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Write PID file for stale detection
	pidFile := filepath.Join(tempDir, "broker.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Define paths within temp directory
	brokerSock := filepath.Join(tempDir, "broker.sock")
	agentDir := filepath.Join(tempDir, "agent")

	// Create agent directory
	if err := os.MkdirAll(agentDir, 0700); err != nil {
		return fmt.Errorf("failed to create agent directory: %w", err)
	}

	// Create broker
	b, err := broker.New(*logger, brokerSock, parent.Auth, parent.CaURL, agentDir, parent.Match, broker.WithTLSConfig(tlsCfg))
	if err != nil {
		return fmt.Errorf("failed to create broker: %w", err)
	}

	// Set up context with cancellation on signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("received shutdown signal")
		cancel()
	}()

	// Generate SSH config file in the temp directory
	sshConfigPath := filepath.Join(tempDir, "ssh-config.conf")

	if err := parent.generateSSHConfig(sshConfigPath, agentDir, brokerSock, homeDir); err != nil {
		logger.Warn("failed to generate SSH config", "error", err, "path", sshConfigPath)
		// Don't fail startup, just warn
	} else {
		// Check if ~/.ssh/config has the Include directive
		includePattern := filepath.Join(homeDir, ".epithet", "run", "*", "ssh-config.conf")
		if err := checkSSHConfigInclude(homeDir, includePattern, logger); err != nil {

			logger.Warn(fmt.Sprintf("Add 'Include %s' to ~/.ssh/config", includePattern))
		}
		logger.Debug("generated SSH config", "path", sshConfigPath)
	}

	// Start broker
	logger.Info("starting broker", "socket", brokerSock, "patterns", parent.Match)
	err = b.Serve(ctx)
	if err != nil && err != context.Canceled {
		return fmt.Errorf("broker serve error: %w", err)
	}

	logger.Info("broker shutdown complete")
	return nil
}

// generateSSHConfig writes an SSH config file for epithet
func (a *AgentCLI) generateSSHConfig(path, agentDir, brokerSock, homeDir string) error {
	// Find epithet binary path
	epithetPath, err := os.Executable()
	if err != nil {
		epithetPath = "epithet" // fallback to PATH
	}

	// Build host pattern list from match patterns
	hostPattern := "*"
	if len(a.Match) > 0 {
		hostPattern = ""
		for i, pattern := range a.Match {
			if i > 0 {
				hostPattern += ","
			}
			hostPattern += pattern
		}
	}

	// Generate include path with full home directory (SSH doesn't expand ~)
	includePattern := filepath.Join(homeDir, ".epithet", "run", "*", "ssh-config.conf")

	config := fmt.Sprintf(`# Generated by epithet agent - do not edit manually
# This file is automatically created when the broker starts and deleted when it stops
# Broker socket: %s
# Agent directory: %s
#
# To use epithet, add the following to ~/.ssh/config:
#   Include %s

Match host %s exec "%s match --host '%%h' --port '%%p' --user '%%r' --jump '%%j' --hash '%%C' --broker '%s'"
    IdentityAgent %s/%%C
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    GSSAPIAuthentication no
    PreferredAuthentications publickey
    IdentityFile /dev/null
`,
		brokerSock,
		agentDir,
		includePattern,
		hostPattern,
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

// expandPath expands ~ to the user's home directory
func expandPath(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if len(path) == 1 {
		return home, nil
	}

	return filepath.Join(home, path[1:]), nil
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
