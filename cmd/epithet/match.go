package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policy"
)

// scannerBufferSize caps how large a single response line from the broker
// may be. Shared with inspect.go's client, whose Inspect responses can carry
// several agents' worth of certificate data and so need the same headroom.
const scannerBufferSize = 1024 * 1024 // 1MiB.

type MatchCLI struct {
	Host   string `help:"Remote host (%h)" short:"H" required:"true"`
	Port   uint   `help:"Remote port (%p)" short:"p" required:"true"`
	User   string `help:"Remote user (%r)" short:"r" required:"true"`
	Hash   string `help:"Connection hash (%C)" short:"C" required:"true"`
	Jump   string `help:"ProxyJump configuration (%j)" short:"j" optional:"true"`
	Broker string `help:"Broker socket path" short:"b" required:"true"`
}

func (m *MatchCLI) Run(logger *slog.Logger) error {
	logger.Debug("match command called", "match", m)

	// Expand broker socket path (handles ~ expansion).
	brokerSock, err := expandPath(m.Broker)
	if err != nil {
		return fmt.Errorf("failed to expand broker socket path: %w", err)
	}

	// Get local hostname.
	localHost, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get local hostname: %w", err)
	}

	// Connect to the broker over its Unix socket and send one request line.
	conn, err := net.Dial("unix", brokerSock)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", brokerSock, err)
	}
	defer conn.Close()

	req := broker.Request{Match: &policy.Connection{
		LocalHost:  localHost,
		RemoteHost: m.Host,
		RemoteUser: m.User,
		Port:       m.Port,
		ProxyJump:  m.Jump,
		Hash:       policy.ConnectionHash(m.Hash),
	}}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("failed to send match request: %w", err)
	}

	// Read response events: zero or more Output lines (written live to
	// stderr as auth progress, e.g. a device-code URL), then one Result.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), scannerBufferSize)

	var result *broker.MatchResponse
	for scanner.Scan() {
		var ev broker.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			return fmt.Errorf("failed to parse broker event: %w", err)
		}
		if ev.Output != "" {
			os.Stderr.WriteString(ev.Output)
		}
		if ev.Result != nil {
			result = ev.Result
			break
		}
	}
	if result == nil {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("broker connection error: %w", err)
		}
		return fmt.Errorf("no result received from broker")
	}

	// Handle response.
	if result.Error != "" {
		return fmt.Errorf("broker error: %s", result.Error)
	}

	if !result.Allow {
		// Not an error - just means epithet doesn't handle this host.
		// Exit silently with non-zero status so SSH knows the match failed.
		os.Exit(1)
	}

	logger.Debug("connection allowed by broker")
	return nil
}
