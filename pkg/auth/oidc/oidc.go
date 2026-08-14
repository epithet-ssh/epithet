// Package oidc performs OIDC/OAuth2 authentication and returns an ID token.
// It is a plain library: callers own how the token state and user-facing
// progress are surfaced (the broker streams progress to ssh sessions; other
// callers may just discard it).
package oidc

import (
	"context"
	"fmt"
	"io"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/int128/oauth2cli"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// Scopes is fixed: nothing in epithet consumes claims beyond email/sub.
var Scopes = []string{"openid", "profile", "email"}

// Config holds OIDC authentication configuration.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string // Optional for PKCE.
	TLSConfig    tlsconfig.Config
}

// Authenticate returns a fresh ID token. prev carries refresh state from the
// previous call (nil on first use); the returned token is the next state.
// User-facing progress ("visit this URL…") is written to out.
func Authenticate(ctx context.Context, cfg Config, prev *oauth2.Token, out io.Writer) (idToken string, next *oauth2.Token, err error) {
	if out == nil {
		// Callers that don't care about progress (e.g. token reuse in tests)
		// shouldn't have to pass a throwaway writer explicitly.
		out = io.Discard
	}

	// Create HTTP client with TLS config and inject into context.
	httpClient, err := tlsconfig.NewHTTPClient(cfg.TLSConfig)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	ctx = oidc.ClientContext(ctx, httpClient)

	// Set up OIDC provider.
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Configure OAuth2.
	oauth2Config := oauth2.Config{
		ClientID: cfg.ClientID,
		// Only set ClientSecret if provided (for PKCE, it should be empty).
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       Scopes,
	}

	var newToken *oauth2.Token

	if prev != nil && prev.Valid() {
		// Token is still valid, use it as-is.
		newToken = prev
	} else if prev != nil && prev.RefreshToken != "" {
		// Try to refresh the token.
		tokenSource := oauth2Config.TokenSource(ctx, prev)
		refreshed, refreshErr := tokenSource.Token()
		if refreshErr != nil {
			// Refresh failed, need full auth.
			fmt.Fprintf(out, "Token refresh failed, performing full authentication: %v\n", refreshErr)
			newToken, err = performFullAuth(ctx, oauth2Config, out)
			if err != nil {
				return "", nil, err
			}
		} else {
			newToken = refreshed
		}
	} else {
		// No valid token, perform full authentication.
		newToken, err = performFullAuth(ctx, oauth2Config, out)
		if err != nil {
			return "", nil, err
		}
	}

	// Extract ID token from the OAuth2 token response.
	// The ID token is a JWT that can be validated by the policy server.
	tok, ok := newToken.Extra("id_token").(string)
	if !ok || tok == "" {
		return "", nil, fmt.Errorf("no id_token in response - ensure 'openid' scope is requested")
	}

	return tok, newToken, nil
}

// performFullAuth performs the full OAuth2 authorization code flow with PKCE.
// It starts a local HTTP server, opens the browser, and waits for the callback.
func performFullAuth(ctx context.Context, oauth2Config oauth2.Config, out io.Writer) (*oauth2.Token, error) {
	// Create a channel to receive the local server URL.
	readyChan := make(chan string, 1)

	// Generate PKCE verifier (random code for this auth flow).
	verifier := oauth2.GenerateVerifier()

	// Use oauth2cli for the CLI authentication flow.
	// It handles:
	// - Starting local HTTP server on random available port
	// - Opening browser
	// - Handling OAuth callback
	cfg := oauth2cli.Config{
		OAuth2Config:         oauth2Config,
		LocalServerReadyChan: readyChan,
		// Let oauth2cli pick an available port automatically.
	}

	// Add PKCE, offline access, and force consent (for refresh tokens).
	cfg.AuthCodeOptions = []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(verifier), // PKCE challenge
		oauth2.AccessTypeOffline,             // Request refresh token
		oauth2.ApprovalForce,                 // Force consent to ensure refresh token
	}

	// Add PKCE verifier to token exchange.
	cfg.TokenRequestOptions = []oauth2.AuthCodeOption{
		oauth2.VerifierOption(verifier), // PKCE verifier
	}

	// Start authentication in background.
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

	// Wait for the local server to be ready, then open browser.
	select {
	case url := <-readyChan:
		// Always surface the URL as user-visible progress, so a session
		// waiting on this flow (including one that joined it after the
		// browser was closed) can complete authentication manually.
		fmt.Fprintf(out, "To authenticate, visit: %s\n", url)
		// Attempt to open the browser.
		if err := browser.OpenURL(url); err != nil {
			// Browser failed to open - user needs the URL to authenticate manually.
			fmt.Fprintf(out, "Could not open browser automatically: %v\n", err)
			fmt.Fprintf(out, "Please visit: %s\n", url)
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Wait for authentication to complete.
	select {
	case token := <-tokenChan:
		return token, nil
	case err := <-errChan:
		return nil, fmt.Errorf("authentication failed: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
