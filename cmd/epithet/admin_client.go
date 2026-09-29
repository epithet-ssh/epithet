package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
)

// ManagementCLI shares agent selection and authenticated transport between
// host inventory and directory administration.
type ManagementCLI struct {
	logger *slog.Logger
	Name   string `help:"Agent profile for administrative commands" name:"agent-name" default:"default"`
	Broker string `help:"Agent broker socket override for administrative commands" name:"broker-socket"`
}

func (c *ManagementCLI) request(req inventoryapi.ControlRequest) (*broker.InventoryResponse, error) {
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
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect to agent: %w; start epithet agent for this profile", err)
	}
	defer conn.Close()
	after := context.AfterFunc(ctx, func() { conn.Close() })
	defer after()
	logger.Debug("sending inventory request to agent")
	if err = json.NewEncoder(conn).Encode(broker.Request{Inventory: &req}); err != nil {
		return nil, err
	}
	logger.Debug("waiting for inventory agent response")
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), inventoryclient.MaxControlResponse)
	for scanner.Scan() {
		var event broker.Event
		if err = json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, err
		}
		if event.Output != "" {
			fmt.Fprint(os.Stderr, event.Output)
		}
		if event.Inventory != nil {
			logger.Debug("received inventory agent response", "elapsed", time.Since(started))
			if event.Inventory.Error != "" {
				return nil, errors.New(event.Inventory.Error)
			}
			return event.Inventory, nil
		}
		if event.Result != nil {
			return nil, fmt.Errorf("agent rejected inventory request: %s", event.Result.Error)
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	return nil, fmt.Errorf("agent closed without an inventory response")
}
