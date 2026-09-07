package oidc

import (
	"context"
	"fmt"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Verifier checks ID tokens independently of inventory identity mapping.
// It can be shared by concurrent callers and caches the provider's signing keys.
type Verifier struct{ verifier *coreoidc.IDTokenVerifier }

// NewVerifier discovers the configured issuer and prepares token verification.
func NewVerifier(ctx context.Context, config Config) (*Verifier, error) {
	if config.IssuerURL == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	client, err := tlsconfig.NewHTTPClient(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	ctx = coreoidc.ClientContext(ctx, client)
	provider, err := coreoidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for %s: %w", config.IssuerURL, err)
	}
	return &Verifier{verifier: provider.Verifier(&coreoidc.Config{ClientID: config.ClientID})}, nil
}

// Verify checks signature, issuer, audience, expiry, and a nonempty subject.
// Callers may inspect claims only after this succeeds.
func (v *Verifier) Verify(ctx context.Context, token string) (*coreoidc.IDToken, error) {
	verified, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	if verified.Subject == "" {
		return nil, fmt.Errorf("OIDC token has no subject")
	}
	return verified, nil
}
