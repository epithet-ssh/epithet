package main

import (
	"fmt"
	"log/slog"
	"net/rpc"
	"os"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policy"
)

type MatchCLI struct {
	Host   string `help:"Remote host (%h)" short:"H" required:"true"`
	Port   uint   `help:"Remote port (%p)" short:"p" required:"true"`
	User   string `help:"Remote user (%r)" short:"r" required:"true"`
	Hash   string `help:"Connection hash (%C)" short:"C" required:"true"`
	Jump   string `help:"ProxyJump configuration (%j)" short:"j" optional:"true"`
	Broker string `help:"Broker socket path" short:"b" default:"~/.epithet/broker.sock"`
}

func (m *MatchCLI) Run(logger *slog.Logger) error {
	logger.Debug("match command called", "match", m)

	// Expand broker socket path (handles ~ expansion)
	brokerSock, err := expandPath(m.Broker)
	if err != nil {
		return fmt.Errorf("failed to expand broker socket path: %w", err)
	}

	// Get local hostname
	localHost, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get local hostname: %w", err)
	}

	// Connect to broker
	client, err := rpc.Dial("unix", brokerSock)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", brokerSock, err)
	}
	defer client.Close()

	// Build request
	req := broker.MatchRequest{
		Connection: policy.Connection{
			LocalHost:  localHost,
			RemoteHost: m.Host,
			RemoteUser: m.User,
			Port:       m.Port,
			ProxyJump:  m.Jump,
			Hash:       policy.ConnectionHash(m.Hash),
		},
	}

	// Call broker
	var resp broker.MatchResponse
	err = client.Call("Broker.Match", req, &resp)
	if err != nil {
		return fmt.Errorf("broker RPC call failed: %w", err)
	}

	// Handle response
	if resp.Error != "" {
		return fmt.Errorf("broker error: %s", resp.Error)
	}

	if !resp.Allow {
		// Not an error - just means epithet doesn't handle this host.
		// Exit silently with non-zero status so SSH knows the match failed.
		os.Exit(1)
	}

	logger.Debug("connection allowed by broker")
	return nil
}
