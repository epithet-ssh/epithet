package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
)

// Config holds OIDC authentication configuration.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string // Optional for PKCE
	Scopes       []string
}

// Run performs OIDC authentication following the epithet auth plugin protocol.
// It reads state from stdin, performs authentication or token refresh,
// writes the access token to stdout, and writes updated state to fd 3.
func Run(ctx context.Context, cfg Config) error {
	// Read state from stdin
	stateBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read state from stdin: %w", err)
	}

	// Try to parse existing token from state
	var token *oauth2.Token
	if len(stateBytes) > 0 {
		token = &oauth2.Token{}
		if err := json.Unmarshal(stateBytes, token); err != nil {
			// Invalid state, need full auth
			token = nil
		}
	}

	// Set up OIDC provider
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Configure OAuth2
	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	var newToken *oauth2.Token

	if token != nil && token.Valid() {
		// Token is still valid, use it as-is
		newToken = token
	} else if token != nil && token.RefreshToken != "" {
		// Try to refresh the token
		tokenSource := oauth2Config.TokenSource(ctx, token)
		refreshed, err := tokenSource.Token()
		if err != nil {
			// Refresh failed, need full auth
			fmt.Fprintf(os.Stderr, "Token refresh failed, performing full authentication: %v\n", err)
			newToken, err = performFullAuth(ctx, oauth2Config)
			if err != nil {
				return err
			}
		} else {
			newToken = refreshed
		}
	} else {
		// No valid token, perform full authentication
		newToken, err = performFullAuth(ctx, oauth2Config)
		if err != nil {
			return err
		}
	}

	// Write access token to stdout (raw bytes, not JSON)
	if _, err := os.Stdout.Write([]byte(newToken.AccessToken)); err != nil {
		return fmt.Errorf("failed to write access token to stdout: %w", err)
	}

	// Write new state to fd 3 (JSON-encoded token)
	stateFd := os.NewFile(3, "state")
	if stateFd == nil {
		return fmt.Errorf("failed to open fd 3 for state output")
	}
	defer stateFd.Close()

	stateJSON, err := json.Marshal(newToken)
	if err != nil {
		return fmt.Errorf("failed to marshal token state: %w", err)
	}

	if _, err := stateFd.Write(stateJSON); err != nil {
		return fmt.Errorf("failed to write state to fd 3: %w", err)
	}

	return nil
}

// performFullAuth performs the full OAuth2 authorization code flow with PKCE.
// It starts a local HTTP server, opens the browser, and waits for the callback.
func performFullAuth(ctx context.Context, oauth2Config oauth2.Config) (*oauth2.Token, error) {
	// Use oauth2cli for the CLI authentication flow
	// It handles:
	// - Starting local HTTP server on random available port
	// - Opening browser
	// - Handling OAuth callback
	// - PKCE
	cfg := oauth2cli.Config{
		OAuth2Config: oauth2Config,
		// Let oauth2cli pick an available port automatically
	}

	// Add PKCE and offline access (for refresh tokens)
	cfg.AuthCodeOptions = []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce, // Force consent to ensure refresh token
	}

	// Notify user that browser is opening
	fmt.Fprintln(os.Stderr, "Opening browser for authentication...")

	// Perform the authentication
	token, err := oauth2cli.GetToken(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Authentication successful!")
	return token, nil
}
