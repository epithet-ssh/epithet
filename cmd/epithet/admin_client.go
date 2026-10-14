package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/facts"
)

// ManagementCLI shares agent selection and authenticated transport between
// host inventory and directory administration.
type ManagementCLI struct {
	logger *slog.Logger
	Name   string `help:"Agent profile for administrative commands" name:"agent-name" default:"default"`
	Broker string `help:"Agent broker socket override for administrative commands" name:"broker-socket"`
}

func (c *ManagementCLI) request(req facts.ControlRequest) (*broker.InventoryResponse, error) {
	logger := c.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("action", req.Action)
	started := time.Now()
	defer func() { logger.Debug("inventory agent request ended", "elapsed", time.Since(started)) }()
	logger.Debug("resolving inventory agent socket")
	socket, err := resolveAgentBrokerSocket(&AgentCLI{Name: c.Name}, c.Broker)
	if err != nil {
		return nil, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	logger.Debug("connecting to inventory agent", "socket", socket)
	response, err := (brokerClient{socket: socket}).manage(ctx, req, os.Stderr)
	if err == nil {
		logger.Debug("received inventory agent response", "elapsed", time.Since(started))
	}
	return response, err
}
