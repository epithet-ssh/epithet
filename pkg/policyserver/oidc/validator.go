package oidc

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	authoidc "github.com/epithet-ssh/epithet/pkg/auth/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Validator validates OIDC JWT tokens.
type Validator struct {
	verifier     *authoidc.Verifier
	issuer       string
	userIDClaim  string
	identityMode IdentityMode
}

// Config configures the OIDC validator.
type Config struct {
	// Issuer is the OIDC provider issuer URL (e.g., "https://accounts.google.com").
	Issuer string

	// ClientID is the expected audience claim. Required: without it, any
	// token issued by the provider for any client would be accepted.
	ClientID string

	// IdentityMode selects how verified claims resolve to an inventory ID.
	IdentityMode IdentityMode

	// UserIDClaim selects a top-level string claim to map to inventory ID.
	// Empty selects the provider default (oid for Entra, sub otherwise).
	UserIDClaim string

	// TLSConfig configures TLS for OIDC provider connections.
	TLSConfig tlsconfig.Config
}

// Claims represents the claims extracted from an OIDC token.
type Claims struct {
	// Issuer is the configured issuer against which the token was verified.
	Issuer string
	// Subject is the stable, case-sensitive identifier within this issuer.
	Subject string
	// UserID is the verified claim value used to look up the inventory user.
	UserID string

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
}

// NewValidator creates a new OIDC token validator.
// It performs OIDC discovery to fetch the provider's JWKS (public keys).
func NewValidator(ctx context.Context, config Config) (*Validator, error) {
	mode, claim, err := ResolveIdentity(config.Issuer, config.IdentityMode, config.UserIDClaim)
	if err != nil {
		return nil, err
	}
	verifier, err := authoidc.NewVerifier(ctx, authoidc.Config{
		IssuerURL: config.Issuer, ClientID: config.ClientID, TLSConfig: config.TLSConfig,
	})
	if err != nil {
		return nil, err
	}

	return &Validator{
		verifier:     verifier,
		issuer:       config.Issuer,
		userIDClaim:  claim,
		identityMode: mode,
	}, nil
}

// Validate validates an OIDC JWT token and extracts claims.
// Returns Claims if the token is valid, error otherwise.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	// Verify token signature and standard claims (including audience and expiry).
	idToken, err := v.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decoding OIDC claims: %w", err)
	}
	userID, ok := raw[v.userIDClaim].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("OIDC user ID claim %q must be a nonempty string", v.userIDClaim)
	}
	if v.identityMode == VerifiedEmail {
		verified, ok := raw["email_verified"].(bool)
		if !ok || !verified {
			return nil, fmt.Errorf("OIDC email_verified must be the boolean true in verified-email mode")
		}
	}
	return &Claims{
		Issuer:    v.issuer,
		Subject:   idToken.Subject,
		UserID:    userID,
		ExpiresAt: idToken.Expiry,
	}, nil
}

// ResolveUserIDClaim uses only the configured issuer, never unverified token
// contents. Entra defaults apply to tenant-specific v1 and v2 issuer URLs.
// Other providers, including Google and Okta, default to the standard sub.
func ResolveUserIDClaim(issuer, override string) string {
	if override != "" {
		return override
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "sub"
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	tenant := strings.ToLower(parts[0])
	if tenant == "" || tenant == "common" || tenant == "organizations" || tenant == "consumers" {
		return "sub"
	}
	switch strings.ToLower(u.Host) {
	case "login.microsoftonline.com", "login.microsoftonline.us", "login.chinacloudapi.cn", "login.partner.microsoftonline.cn":
		if len(parts) == 2 && parts[1] == "v2.0" {
			return "oid"
		}
	case "sts.windows.net":
		if len(parts) == 1 {
			return "oid"
		}
	}
	return "sub"
}
