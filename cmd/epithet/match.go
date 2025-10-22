package main

import (
	"fmt"
	"log/slog"
	"net/rpc"
	"os"
	"os/user"

	"github.com/epithet-ssh/epithet/pkg/broker"
)

type MatchCLI struct {
	Host      string `help:"Remote host (%h)" required:"true"`
	Port      uint   `help:"Remote port (%p)" required:"true"`
	User      string `help:"Remote user (%r)" required:"true"`
	Hash      string `help:"Connection hash (%C)" required:"true"`
	ProxyJump string `help:"ProxyJump configuration (%j)" default:""`
	Broker    string `help:"Broker socket path" default:"~/.epithet/broker.sock"`
}

func (m *MatchCLI) Run(logger *slog.Logger) error {
	logger.Debug("match command called", "match", m)

	// Get local hostname
	localHost, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get local hostname: %w", err)
	}

	// Get local user
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Connect to broker
	client, err := rpc.Dial("unix", m.Broker)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", m.Broker, err)
	}
	defer client.Close()

	// Build request
	req := broker.MatchRequest{
		LocalHost:      localHost,
		LocalUser:      currentUser.Username,
		RemoteHost:     m.Host,
		RemoteUser:     m.User,
		Port:           m.Port,
		ProxyJump:      m.ProxyJump,
		ConnectionHash: m.Hash,
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
