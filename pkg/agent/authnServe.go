package agent

import (
	"context"

	rpc "github.com/epithet-ssh/epithet/internal/agent"
)

type authnServe struct {
	a *Agent
}

func (s *authnServe) Authenticate(ctx context.Context, req *rpc.AuthnRequest) (*rpc.AuthnResponse, error) {
	err := s.a.RequestCertificate(ctx, req.GetToken())
	if err != nil {
		return nil, err
	}
	return &rpc.AuthnResponse{}, nil
}
