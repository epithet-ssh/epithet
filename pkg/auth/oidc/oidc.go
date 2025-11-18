package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/int128/oauth2cli"
	"github.com/pkg/browser"
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
		ClientID: cfg.ClientID,
		// Only set ClientSecret if provided (for PKCE, it should be empty)
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

	// Extract ID token from the OAuth2 token response
	// The ID token is a JWT that can be validated by the policy server
	idToken, ok := newToken.Extra("id_token").(string)
	if !ok || idToken == "" {
		return fmt.Errorf("no id_token in response - ensure 'openid' scope is requested")
	}

	// Write ID token to stdout (raw bytes, not JSON)
	if _, err := os.Stdout.Write([]byte(idToken)); err != nil {
		return fmt.Errorf("failed to write ID token to stdout: %w", err)
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
	// Create a channel to receive the local server URL
	readyChan := make(chan string, 1)

	// Generate PKCE verifier (random code for this auth flow)
	verifier := oauth2.GenerateVerifier()

	// Use oauth2cli for the CLI authentication flow
	// It handles:
	// - Starting local HTTP server on random available port
	// - Opening browser
	// - Handling OAuth callback
	cfg := oauth2cli.Config{
		OAuth2Config:         oauth2Config,
		LocalServerReadyChan: readyChan,
		// Let oauth2cli pick an available port automatically
	}

	// Add PKCE, offline access, and force consent (for refresh tokens)
	cfg.AuthCodeOptions = []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(verifier), // PKCE challenge
		oauth2.AccessTypeOffline,             // Request refresh token
		oauth2.ApprovalForce,                 // Force consent to ensure refresh token
	}

	// Add PKCE verifier to token exchange
	cfg.TokenRequestOptions = []oauth2.AuthCodeOption{
		oauth2.VerifierOption(verifier), // PKCE verifier
	}

	// Notify user that browser is opening
	fmt.Fprintln(os.Stderr, "Opening browser for authentication...")

	// Start authentication in background
	tokenChan := make(chan *oauth2.Token, 1)
	errChan := make(chan error, 1)
	go func() {
		token, err := oauth2cli.GetToken(ctx, cfg)
		if err != nil {
			errChan <- err
			return
		}
		tokenChan <- token
	}()

	// Wait for the local server to be ready, then open browser
	select {
	case url := <-readyChan:
		fmt.Fprintf(os.Stderr, "\nIf your browser doesn't open automatically, visit:\n%s\n\n", url)
		// Attempt to open the browser
		if err := browser.OpenURL(url); err != nil {
			fmt.Fprintf(os.Stderr, "Could not open browser automatically: %v\n", err)
			fmt.Fprintf(os.Stderr, "Please open the URL above manually.\n")
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Wait for authentication to complete
	select {
	case token := <-tokenChan:
		fmt.Fprintln(os.Stderr, "Authentication successful!")
		return token, nil
	case err := <-errChan:
		return nil, fmt.Errorf("authentication failed: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
