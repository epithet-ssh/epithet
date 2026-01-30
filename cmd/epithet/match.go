package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	pb "github.com/epithet-ssh/epithet/pkg/brokerv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	// Connect to broker via gRPC over Unix socket.
	conn, err := grpc.NewClient(
		"unix://"+brokerSock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", brokerSock, err)
	}
	defer conn.Close()

	client := pb.NewBrokerServiceClient(conn)

	// Build request.
	req := &pb.MatchRequest{
		Connection: &pb.Connection{
			LocalHost:  localHost,
			RemoteHost: m.Host,
			RemoteUser: m.User,
			Port:       uint32(m.Port),
			ProxyJump:  m.Jump,
			Hash:       m.Hash,
		},
	}

	// Call broker with streaming to receive user output and result.
	stream, err := client.Match(context.Background(), req)
	if err != nil {
		return fmt.Errorf("broker RPC call failed: %w", err)
	}

	// Process stream events.
	var result *pb.MatchResult
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("stream error: %w", err)
		}

		switch e := event.Event.(type) {
		case *pb.MatchEvent_UserOutput:
			// Write auth command user output to our stderr for display.
			os.Stderr.Write(e.UserOutput)
		case *pb.MatchEvent_Result:
			result = e.Result
		}
	}

	if result == nil {
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
