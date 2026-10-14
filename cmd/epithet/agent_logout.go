package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"
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
	response, err := (brokerClient{socket: socket}).logout(ctx)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Logged out; cleared %d certificate agents.\n", response.AgentsCleared)
	return err
}
