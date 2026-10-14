package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/epithet-ssh/epithet/pkg/wire"
)

// MatchCLI receives connection inputs from SSH's generated command line.
// These flags must have no environment bindings; loadCLIConfig excludes them
// from file configuration. Global flags retain their normal configuration.
type MatchCLI struct {
	Host   string `help:"Remote host (%h)" short:"H" required:"true"`
	Port   uint   `help:"Remote port (%p)" short:"p" required:"true"`
	User   string `help:"Remote user (%r)" short:"r" required:"true"`
	Hash   string `help:"Connection hash (%C)" short:"C" required:"true"`
	Jump   string `help:"ProxyJump configuration (%j)" short:"j" optional:"true"`
	Broker string `help:"Broker socket path" short:"b" required:"true" name:"broker-socket"`
}

func (m *MatchCLI) Run(logger *slog.Logger) error {
	logger.Debug("match command called", "match", m)

	// Expand broker socket path (handles ~ expansion).
	brokerSock, err := expandPath(m.Broker)
	if err != nil {
		return fmt.Errorf("failed to expand broker socket path: %w", err)
	}

	result, err := (brokerClient{socket: brokerSock}).match(context.Background(), wire.Connection{
		RemoteHost: m.Host,
		RemoteUser: m.User,
		Port:       m.Port,
		ProxyJump:  m.Jump,
		Hash:       wire.ConnectionHash(m.Hash),
	}, os.Stderr)
	if err != nil {
		return err
	}

	// Handle response. Allow alone drives the exit code; Error is a message
	// to surface to the user, not necessarily a failure - the broker can set
	// both when it denies the match with an explanation.
	if result.Error != "" {
		fmt.Fprintln(os.Stderr, result.Error)
	}

	if !result.Allow {
		// Not an error - just means the broker denied the match.
		// Exit silently with non-zero status so SSH knows the match failed.
		os.Exit(1)
	}

	logger.Debug("connection allowed by broker")
	return nil
}
