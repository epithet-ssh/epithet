package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"
)

type AgentLoginCLI struct {
	Broker string `help:"Broker socket path (overrides profile discovery)" short:"b" name:"broker-socket"`
}

func (c *AgentLoginCLI) Run(parent *AgentCLI) error {
	socket, err := resolveAgentBrokerSocket(parent, c.Broker)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return c.run(ctx, socket, os.Stdout, os.Stderr)
}

func (c *AgentLoginCLI) run(ctx context.Context, socket string, out, progress io.Writer) error {
	if _, err := authenticateAgent(ctx, socket, progress); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, "Logged in.")
	return err
}
