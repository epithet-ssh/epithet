package agent

import (
	"fmt"

	"google.golang.org/grpc"
)

//go:generate protoc --proto_path=../../proto/ --go_out=. --go-grpc_out=. --go-grpc_opt=paths=source_relative --go_opt=paths=source_relative agent.proto

// NewClient creates  anew RPC client for an Agent
func NewClient(path string) (AgentServiceClient, error) {
	conn, err := grpc.Dial(fmt.Sprintf("unix:%s", path), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	client := NewAgentServiceClient(conn)
	return client, nil
}
