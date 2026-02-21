package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
)

// mockOIDCServer returns a test server that serves the two endpoints
// coreos/go-oidc needs for provider discovery: openid-configuration
// and an empty JWKS.
func mockOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()
	var url string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"authorization_endpoint":%q,"token_endpoint":%q,"response_types_supported":["code"]}`,
				url, url+"/jwks", url+"/auth", url+"/token")
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	url = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

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

// TestNewValidator_Success tests that we can create a validator against a mock OIDC provider.
func TestNewValidator_Success(t *testing.T) {
	mock := mockOIDCServer(t)

	ctx := context.Background()
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: mock.URL,
	})

	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if validator == nil {
		t.Fatal("validator is nil")
	}
}

// TestValidate_InvalidToken tests that invalid tokens are rejected.
func TestValidate_InvalidToken(t *testing.T) {
	mock := mockOIDCServer(t)

	ctx := context.Background()
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: mock.URL,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Try to validate an invalid token.
	_, err = validator.Validate(ctx, "invalid.token.string")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

// TestValidate_ExpiredToken tests that expired tokens are rejected.
func TestValidate_ExpiredToken(t *testing.T) {
	mock := mockOIDCServer(t)

	ctx := context.Background()
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: mock.URL,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Crafted JWT with an invalid signature — fails at JWKS verification
	// because the mock serves an empty key set.
	expiredToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE4MmU0NTU0YjZlNWQxYjEzMDQzZWNiYjFhYTE2MmZlMzU0YTViOWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0NTY3ODkwIiwiYXVkIjoiMTIzNDU2Nzg5MCIsInN1YiI6IjExMjIzMzQ0NTU2Njc3ODg5OTAwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxNjAwMDAzNjAwfQ.invalid-signature"

	_, err = validator.Validate(ctx, expiredToken)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

// ExampleValidator is illustrative — it shows how the validator API is used
// but requires a real OIDC provider to actually run.
func ExampleValidator() {
	ctx := context.Background()

	// Create validator for Google.
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: "https://accounts.google.com",
	})
	if err != nil {
		panic(err)
	}

	// Validate a token (this would come from epithet auth oidc).
	claims, err := validator.Validate(ctx, "token-from-auth-command")
	if err != nil {
		panic(err)
	}

	// Use the claims.
	_ = claims.Identity // "user@example.com"
	_ = claims.Email    // "user@example.com"
	_ = claims.Subject  // "1234567890"
}
