package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Validator validates OIDC JWT tokens.
type Validator struct {
	verifier *oidc.IDTokenVerifier
}

// Config configures the OIDC validator.
type Config struct {
	// Issuer is the OIDC provider issuer URL (e.g., "https://accounts.google.com").
	Issuer string

	// ClientID is the expected audience claim. Required: without it, any
	// token issued by the provider for any client would be accepted.
	ClientID string

	// TLSConfig configures TLS for OIDC provider connections.
	TLSConfig tlsconfig.Config
}

// Claims represents the claims extracted from an OIDC token.
type Claims struct {
	// Identity is the user's identity, extracted from the email claim (or sub if email not present).
	Identity string

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
}

// NewValidator creates a new OIDC token validator.
// It performs OIDC discovery to fetch the provider's JWKS (public keys).
func NewValidator(ctx context.Context, config Config) (*Validator, error) {
	if config.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	// Create HTTP client with TLS config and inject into context.
	httpClient, err := tlsconfig.NewHTTPClient(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	ctx = oidc.ClientContext(ctx, httpClient)

	// Perform OIDC discovery.
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for %s: %w", config.Issuer, err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &Validator{
		verifier: verifier,
	}, nil
}

// Validate validates an OIDC JWT token and extracts claims.
// Returns Claims if the token is valid, error otherwise.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	// Verify token signature and standard claims (including audience and expiry).
	idToken, err := v.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Extract all claims into a map to look for the email claim.
	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	claims := &Claims{
		ExpiresAt: idToken.Expiry,
	}

	// Extract email claim (preferred for identity), falling back to subject.
	if email, ok := allClaims["email"].(string); ok {
		claims.Identity = email
	} else {
		claims.Identity = idToken.Subject
	}

	return claims, nil
}
