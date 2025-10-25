package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/epithet-ssh/epithet/pkg/broker"
)

type AgentCLI struct {
	Match        []string `help:"Match patterns" short:"m" required:"true"`
	CaURL        string   `help:"CA URL" name:"ca-url" short:"c" required:"true"`
	Auth         string   `help:"Authentication command" short:"a" required:"true"`
	BrokerSock   string   `help:"Broker socket path" name:"broker-sock" short:"b" default:"~/.epithet/broker.sock"`
	AgentSockDir string   `help:"Agent socket directory" name:"agent-sock-dir" default:"~/.epithet/sockets"`
}

func (a *AgentCLI) Run(logger *slog.Logger) error {
	logger.Debug("agent command received", "agent", a)

	// Expand home directory in paths
	brokerSock, err := expandPath(a.BrokerSock)
	if err != nil {
		return fmt.Errorf("failed to expand broker socket path: %w", err)
	}

	agentSockDir, err := expandPath(a.AgentSockDir)
	if err != nil {
		return fmt.Errorf("failed to expand agent socket directory: %w", err)
	}

	// Create broker
	b := broker.New(*logger, brokerSock, a.Auth, a.CaURL, agentSockDir, a.Match)

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

	// Start broker
	logger.Info("starting broker", "socket", brokerSock, "patterns", a.Match)
	err = b.Serve(ctx)
	if err != nil && err != context.Canceled {
		return fmt.Errorf("broker serve error: %w", err)
	}

	logger.Info("broker shutdown complete")
	return nil
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
