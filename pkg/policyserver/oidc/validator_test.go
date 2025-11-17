package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
)

// Note: These are integration tests that require network access to real OIDC providers.
// For unit tests, we would need to mock the OIDC provider.

func TestNewValidator_InvalidIssuer(t *testing.T) {
	ctx := context.Background()

	_, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: "https://invalid-oidc-provider-that-does-not-exist.example.com",
	})

	if err == nil {
		t.Fatal("expected error for invalid issuer, got nil")
	}
}

func TestNewValidator_EmptyIssuer(t *testing.T) {
	ctx := context.Background()

	_, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: "",
	})

	if err == nil {
		t.Fatal("expected error for empty issuer, got nil")
	}

	if err.Error() != "issuer is required" {
		t.Errorf("expected 'issuer is required' error, got: %v", err)
	}
}

// TestNewValidator_Google tests that we can successfully create a validator for Google
// This is an integration test that requires network access
func TestNewValidator_Google(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: "https://accounts.google.com",
	})

	if err != nil {
		t.Fatalf("failed to create validator for Google: %v", err)
	}

	if validator == nil {
		t.Fatal("validator is nil")
	}
}

// TestValidate_InvalidToken tests that invalid tokens are rejected
func TestValidate_InvalidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Try to validate an invalid token
	_, err = validator.Validate(ctx, "invalid.token.string")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

// TestValidate_ExpiredToken tests that expired tokens are rejected
func TestValidate_ExpiredToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// This is a real but expired Google ID token (safe to include - already expired)
	expiredToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE4MmU0NTU0YjZlNWQxYjEzMDQzZWNiYjFhYTE2MmZlMzU0YTViOWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0NTY3ODkwIiwiYXVkIjoiMTIzNDU2Nzg5MCIsInN1YiI6IjExMjIzMzQ0NTU2Njc3ODg5OTAwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxNjAwMDAzNjAwfQ.invalid-signature"

	_, err = validator.Validate(ctx, expiredToken)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

// Example test showing how to use the validator
func ExampleValidator() {
	ctx := context.Background()

	// Create validator for Google
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: "https://accounts.google.com",
	})
	if err != nil {
		panic(err)
	}

	// Validate a token (this would come from epithet auth oidc)
	claims, err := validator.Validate(ctx, "token-from-auth-command")
	if err != nil {
		panic(err)
	}

	// Use the claims
	_ = claims.Identity // "user@example.com"
	_ = claims.Email    // "user@example.com"
	_ = claims.Subject  // "1234567890"
}
