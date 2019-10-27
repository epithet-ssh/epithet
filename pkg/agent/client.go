package agent

import (
	"fmt"

	"github.com/brianm/epithet/pkg/agent/rpc"
	"google.golang.org/grpc"
)

// NewClient creates  anew RPC client for an Agent
func NewClient(path string) (rpc.AgentServiceClient, error) {
	conn, err := grpc.Dial(fmt.Sprintf("unix:%s", path), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	client := rpc.NewAgentServiceClient(conn)
	return client, nil
}
