package main

import (
	"fmt"
	"log/slog"
	"net/rpc"
	"os"
	"os/user"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policy"
)

type MatchCLI struct {
	Host      string `help:"Remote host (%h)" short:"H" required:"true"`
	Port      uint   `help:"Remote port (%p)" short:"p" required:"true"`
	User      string `help:"Remote user (%r)" short:"r" required:"true"`
	LocalUser string `help:"Local user (%l)" short:"l" default:""`
	Hash      string `help:"Connection hash (%C)" short:"C" required:"true"`
	ProxyJump string `help:"ProxyJump configuration (%j)" short:"j" default:""`
	Broker    string `help:"Broker socket path" short:"b" default:"~/.epithet/broker.sock"`
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

	// Get local user - use CLI arg if provided, otherwise current user
	localUser := m.LocalUser
	if localUser == "" {
		currentUser, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to get current user: %w", err)
		}
		localUser = currentUser.Username
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
			LocalUser:  localUser,
			RemoteHost: m.Host,
			RemoteUser: m.User,
			Port:       m.Port,
			ProxyJump:  m.ProxyJump,
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
		logger.Error("broker returned error", "error", resp.Error)
		return fmt.Errorf("broker error: %s", resp.Error)
	}

	if !resp.Allow {
		logger.Info("connection not allowed by broker")
		return fmt.Errorf("connection denied by broker")
	}

	logger.Debug("connection allowed by broker")
	return nil
}
