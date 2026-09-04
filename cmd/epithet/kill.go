package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policy"
)

// AgentKillCLI evicts one per-connection agent from the running broker.
type AgentKillCLI struct {
	Broker  string                `help:"Broker socket path (overrides config-based discovery)" short:"b"`
	AgentID policy.ConnectionHash `arg:"" name:"agent-id" help:"Agent ID shown by epithet agent inspect" required:""`
}

func (k *AgentKillCLI) Run(parent *AgentCLI) error {
	brokerSock, err := resolveAgentBrokerSocket(parent, k.Broker)
	if err != nil {
		return err
	}

	conn, err := net.Dial("unix", brokerSock)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", brokerSock, err)
	}
	defer conn.Close()

	resp, err := requestAgentKill(conn, k.AgentID)
	if err != nil {
		return err
	}
	writeAgentKill(os.Stdout, resp)
	return nil
}

func requestAgentKill(conn net.Conn, id policy.ConnectionHash) (*broker.KillResponse, error) {
	if err := json.NewEncoder(conn).Encode(broker.Request{Kill: &broker.KillRequest{ID: id}}); err != nil {
		return nil, fmt.Errorf("failed to send kill request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), scannerBufferSize)
	for scanner.Scan() {
		var event broker.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("failed to parse broker event: %w", err)
		}
		if event.Kill != nil {
			if event.Kill.Error != "" {
				return nil, fmt.Errorf("broker refused to kill agent: %s", event.Kill.Error)
			}
			return event.Kill, nil
		}
		if event.Result != nil {
			return nil, fmt.Errorf("broker error: %s", event.Result.Error)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("broker connection error: %w", err)
	}
	return nil, fmt.Errorf("no response received from broker")
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
