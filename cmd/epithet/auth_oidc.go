package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/auth/oidc"
)

// AuthOIDCCLI implements the "epithet auth oidc" command for OIDC/OAuth2 authentication.
type AuthOIDCCLI struct {
	Issuer       string   `required:"" help:"OIDC issuer URL (e.g., https://accounts.google.com)"`
	ClientID     string   `required:"" name:"client-id" help:"OAuth2 client ID"`
	ClientSecret string   `optional:"" name:"client-secret" help:"OAuth2 client secret (optional if using PKCE)"`
	Scopes       []string `optional:"" help:"OAuth2 scopes (comma-separated)" default:"openid,profile,email"`
}

// Run executes the OIDC authentication flow following the epithet auth plugin protocol.
//
// Protocol:
//   - stdin: JSON-encoded oauth2.Token from previous invocation (empty on first call)
//   - stdout: access token (raw bytes)
//   - fd 3: new JSON-encoded oauth2.Token for next invocation
//   - stderr: human-readable messages and errors
//   - exit 0: success, non-zero: failure
func (c *AuthOIDCCLI) Run(logger *slog.Logger) error {
	// Set a reasonable timeout for the entire auth flow
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Parse scopes (handle both comma-separated and multiple values)
	scopes := make([]string, 0)
	for _, scope := range c.Scopes {
		parts := strings.Split(scope, ",")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				scopes = append(scopes, trimmed)
			}
		}
	}

	// Ensure we always have at least openid scope
	hasOpenID := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		scopes = append([]string{"openid"}, scopes...)
	}

	logger.Debug("starting OIDC authentication",
		"issuer", c.Issuer,
		"client_id", c.ClientID,
		"scopes", scopes,
	)

	// Configure OIDC
	cfg := oidc.Config{
		IssuerURL:    c.Issuer,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       scopes,
	}

	// Run the authentication flow
	if err := oidc.Run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
		return err
	}

	logger.Debug("OIDC authentication completed successfully")
	return nil
}
