package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
)

type AgentLogoutCLI struct {
	Broker string `help:"Broker socket path (overrides profile discovery)" short:"b" name:"broker-socket"`
}

func (c *AgentLogoutCLI) Run(parent *AgentCLI) error {
	socket, err := resolveAgentBrokerSocket(parent, c.Broker)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return c.run(ctx, socket, os.Stdout)
}

func (c *AgentLogoutCLI) run(ctx context.Context, socket string, out io.Writer) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("cannot connect to agent at %s; start it with epithet agent: %w", socket, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(broker.Request{Logout: &struct{}{}}); err != nil {
		return fmt.Errorf("sending logout request: %w", err)
	}
	var event broker.Event
	if err := json.NewDecoder(conn).Decode(&event); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("reading agent logout: %w", err)
	}
	if event.Logout == nil {
		return fmt.Errorf("agent returned no logout response; restart the agent if it predates logout support")
	}
	if event.Logout.Error != "" {
		return fmt.Errorf("agent logout: %s", event.Logout.Error)
	}
	_, err = fmt.Fprintf(out, "Logged out; cleared %d certificate agents.\n", event.Logout.AgentsCleared)
	return err
}
