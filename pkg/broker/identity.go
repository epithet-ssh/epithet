package broker

import (
	"context"
	"fmt"
	"io"
)

// Identity reports selected claims from a verified token, never bearer credentials.
// EmailVerified is the issuer assertion, not an inventory authorization decision.
type Identity struct {
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	OID           string `json:"oid,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}

// IdentityResponse is the terminal event for an identity request.
type IdentityResponse struct {
	Identity *Identity `json:"identity,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// IdentityVerifier verifies the agent's ID token and extracts diagnostic claims.
// It must be safe for concurrent calls and must not return token contents in errors.
type IdentityVerifier func(context.Context, string) (*Identity, error)

// WithIdentityVerifier enables identity requests using the agent's configured
// issuer and audience.
func WithIdentityVerifier(verify IdentityVerifier) Option {
	return optionFunc(func(b *Broker) error {
		if verify == nil {
			return fmt.Errorf("identity verifier is required")
		}
		b.verifyIdentity = verify
		return nil
	})
}

// IdentityWithUserOutput authenticates through the same cache and in-flight
// login as SSH requests. It does not request a certificate or require an
// inventory record, so administrators can use it to prepare that record.
func (b *Broker) IdentityWithUserOutput(ctx context.Context, out io.Writer) IdentityResponse {
	if b.verifyIdentity == nil {
		return IdentityResponse{Error: "agent identity is unavailable; restart the agent with identity support"}
	}
	token, err := b.auth.Token(ctx, out)
	if err != nil {
		return IdentityResponse{Error: fmt.Sprintf("agent authentication failed: %v", err)}
	}
	identity, err := b.verifyIdentity(ctx, token)
	if err != nil {
		return IdentityResponse{Error: fmt.Sprintf("verifying agent identity: %v", err)}
	}
	return IdentityResponse{Identity: identity}
}
