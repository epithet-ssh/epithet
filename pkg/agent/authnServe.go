package agent

import (
	"context"

	"github.com/brianm/epithet/pkg/authn"
	"github.com/brianm/epithet/pkg/caserver"
)

type authnServe struct {
	a *Agent
}

func (s *authnServe) Authenticate(ctx context.Context, req *authn.AuthnRequest) (*authn.AuthnResponse, error) {
	res, err := s.a.caClient.GetCert(ctx, &caserver.CreateCertRequest{
		PublicKey: s.a.publicKey,
		Token:     req.GetToken(),
	})

	if err != nil {
		return nil, err
	}

	err = s.a.UseCredential(Credential{
		PrivateKey:  s.a.privateKey,
		Certificate: res.Certificate,
	})
	if err != nil {
		return nil, err
	}

	return &authn.AuthnResponse{}, nil
}
