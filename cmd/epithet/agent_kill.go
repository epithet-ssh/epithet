package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// AgentKillCLI evicts one per-connection agent from the running broker.
type AgentKillCLI struct {
	Broker  string              `help:"Broker socket path (overrides config-based discovery)" short:"b" name:"broker-socket"`
	AgentID wire.ConnectionHash `arg:"" name:"agent-id" help:"Agent ID or unique prefix shown by epithet agent inspect" required:""`
}

func (k *AgentKillCLI) Run(parent *AgentCLI) error {
	brokerSock, err := resolveAgentBrokerSocket(parent, k.Broker)
	if err != nil {
		return err
	}

	resp, err := (brokerClient{socket: brokerSock}).kill(context.Background(), k.AgentID)
	if err != nil {
		return err
	}
	writeAgentKill(os.Stdout, resp)
	return nil
}

func writeAgentKill(w io.Writer, resp *broker.KillResponse) {
	fmt.Fprintf(w, "Killed agent %s", resp.ID)
	if resp.Connection.RemoteHost != "" {
		fmt.Fprintf(w, " (%s@%s", resp.Connection.RemoteUser, resp.Connection.RemoteHost)
		if resp.Connection.Port != 0 {
			fmt.Fprintf(w, ":%d", resp.Connection.Port)
		}
		fmt.Fprint(w, ")")
	}
	fmt.Fprintln(w)
}
