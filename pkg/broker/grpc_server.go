package broker

import (
	"context"
	"path/filepath"

	pb "github.com/epithet-ssh/epithet/pkg/brokerv1"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BrokerServer implements the gRPC BrokerService interface.
type BrokerServer struct {
	pb.UnimplementedBrokerServiceServer
	broker *Broker
}

// NewBrokerServer creates a new gRPC server wrapping the given Broker.
func NewBrokerServer(broker *Broker) *BrokerServer {
	return &BrokerServer{broker: broker}
}

// Match implements the BrokerService Match RPC.
// It streams stderr from the auth command (if any) and returns the final result.
func (s *BrokerServer) Match(req *pb.MatchRequest, stream grpc.ServerStreamingServer[pb.MatchEvent]) error {
	conn := protoToConnection(req.Connection)

	// Run the match logic with stderr streaming.
	result := s.broker.MatchWithStderr(conn, func(stderr []byte) error {
		return stream.Send(&pb.MatchEvent{
			Event: &pb.MatchEvent_Stderr{Stderr: stderr},
		})
	})

	// Send the final result.
	return stream.Send(&pb.MatchEvent{
		Event: &pb.MatchEvent_Result{Result: &pb.MatchResult{
			Allow: result.Allow,
			Error: result.Error,
		}},
	})
}

// Inspect implements the BrokerService Inspect RPC.
func (s *BrokerServer) Inspect(ctx context.Context, req *pb.InspectRequest) (*pb.InspectResponse, error) {
	// Use the existing Inspect logic.
	var resp InspectResponse
	if err := s.broker.Inspect(InspectRequest{}, &resp); err != nil {
		return nil, err
	}

	return inspectResponseToProto(&resp), nil
}

// protoToConnection converts a proto Connection to policy.Connection.
func protoToConnection(c *pb.Connection) policy.Connection {
	if c == nil {
		return policy.Connection{}
	}
	return policy.Connection{
		LocalHost:  c.LocalHost,
		RemoteHost: c.RemoteHost,
		RemoteUser: c.RemoteUser,
		Port:       uint(c.Port),
		ProxyJump:  c.ProxyJump,
		Hash:       policy.ConnectionHash(c.Hash),
	}
}

// inspectResponseToProto converts an InspectResponse to the proto equivalent.
func inspectResponseToProto(resp *InspectResponse) *pb.InspectResponse {
	agents := make([]*pb.AgentInfo, len(resp.Agents))
	for i, a := range resp.Agents {
		agents[i] = &pb.AgentInfo{
			Hash:        a.Hash,
			SocketPath:  a.SocketPath,
			ExpiresAt:   timestamppb.New(a.ExpiresAt),
			Certificate: string(a.Certificate),
		}
	}

	certs := make([]*pb.CertInfo, len(resp.Certificates))
	for i, c := range resp.Certificates {
		hostUsers := make(map[string]*pb.StringList)
		for pattern, users := range c.Policy.HostUsers {
			hostUsers[pattern] = &pb.StringList{Values: users}
		}
		certs[i] = &pb.CertInfo{
			Certificate: string(c.Certificate),
			HostUsers:   hostUsers,
			ExpiresAt:   timestamppb.New(c.ExpiresAt),
		}
	}

	return &pb.InspectResponse{
		SocketPath:        resp.SocketPath,
		AgentSocketDir:    resp.AgentSocketDir,
		DiscoveryPatterns: resp.DiscoveryPatterns,
		Agents:            agents,
		Certificates:      certs,
	}
}

// agentSocketPathForHash returns the socket path for a connection hash.
func (s *BrokerServer) agentSocketPathForHash(hash string) string {
	return filepath.Join(s.broker.agentSocketDir, hash)
}
