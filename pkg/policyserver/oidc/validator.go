package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"golang.org/x/oauth2"
)

// Validator validates OIDC JWT tokens
type Validator struct {
	verifier *oidc.IDTokenVerifier
	issuer   string
}

// Config configures the OIDC validator
type Config struct {
	// Issuer is the OIDC provider issuer URL (e.g., "https://accounts.google.com")
	Issuer string

	// ClientID is the expected audience claim (optional, not always required)
	ClientID string

	// SkipExpiryCheck disables token expiration validation (not recommended for production)
	SkipExpiryCheck bool

	// TLSConfig configures TLS for OIDC provider connections
	TLSConfig tlsconfig.Config
}

// Claims represents the claims extracted from an OIDC token
type Claims struct {
	// Identity is the user's identity, extracted from email claim (or sub if email not present)
	Identity string

	// Email is the user's email address (if present in token)
	Email string

	// Subject is the subject claim (unique user identifier)
	Subject string

	// Issuer is the issuer claim (should match configured issuer)
	Issuer string

	// Audience is the audience claim (who the token is intended for)
	Audience []string

	// ExpiresAt is when the token expires
	ExpiresAt time.Time

	// IssuedAt is when the token was issued
	IssuedAt time.Time
}

// NewValidator creates a new OIDC token validator.
// It performs OIDC discovery to fetch the provider's JWKS (public keys).
func NewValidator(ctx context.Context, config Config) (*Validator, error) {
	if config.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	// Create HTTP client with TLS config and inject into context
	httpClient, err := tlsconfig.NewHTTPClient(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	ctx = oidc.ClientContext(ctx, httpClient)

	// Perform OIDC discovery
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for %s: %w", config.Issuer, err)
	}

	// Create ID token verifier
	verifierConfig := &oidc.Config{
		SkipExpiryCheck: config.SkipExpiryCheck,
	}

	if config.ClientID != "" {
		verifierConfig.ClientID = config.ClientID
	} else {
		// If no client ID provided, skip audience verification
		verifierConfig.SkipClientIDCheck = true
	}

	verifier := provider.Verifier(verifierConfig)

	return &Validator{
		verifier: verifier,
		issuer:   config.Issuer,
	}, nil
}

// Validate validates an OIDC JWT token and extracts claims.
// Returns Claims if token is valid, error otherwise.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	// Verify token signature and standard claims
	idToken, err := v.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Extract all claims into a map
	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	// Extract standard claims
	claims := &Claims{
		Subject:   idToken.Subject,
		Issuer:    idToken.Issuer,
		Audience:  idToken.Audience,
		ExpiresAt: idToken.Expiry,
		IssuedAt:  idToken.IssuedAt,
	}

	// Extract email claim (preferred for identity)
	if email, ok := allClaims["email"].(string); ok {
		claims.Email = email
		claims.Identity = email
	} else {
		// Fall back to subject if email not present
		claims.Identity = idToken.Subject
	}

	return claims, nil
}

// ValidateAccessToken validates an OAuth2 access token.
// This is a convenience wrapper that handles both ID tokens and access tokens.
// For access tokens, it uses the UserInfo endpoint to get user information.
func (v *Validator) ValidateAccessToken(ctx context.Context, accessToken string) (*Claims, error) {
	// First try as ID token
	claims, err := v.Validate(ctx, accessToken)
	if err == nil {
		return claims, nil
	}

	// If that fails, try using UserInfo endpoint
	// This requires creating a provider again (not ideal, but works)
	provider, err := oidc.NewProvider(ctx, v.issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider for UserInfo: %w", err)
	}

	// Create OAuth2 token
	oauth2Token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}

	// Query UserInfo endpoint
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Extract claims from UserInfo
	var allClaims map[string]any
	if err := userInfo.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("failed to extract UserInfo claims: %w", err)
	}

	claims = &Claims{
		Subject: userInfo.Subject,
		Issuer:  v.issuer,
	}

	// Extract email claim
	if email, ok := allClaims["email"].(string); ok {
		claims.Email = email
		claims.Identity = email
	} else {
		claims.Identity = userInfo.Subject
	}

	return claims, nil
}
