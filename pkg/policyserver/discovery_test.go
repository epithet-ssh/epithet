package policyserver_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

func TestDiscoveryHandler_Success(t *testing.T) {
	validator := &mockValidator{}
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: []string{"*.example.com", "prod-*"},
		AuthHash:      "abc123",
		UnauthHash:    "xyz789",
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc", Issuer: "https://example.com", ClientID: "test"},
	})

	// Token must be base64url-encoded (as broker encodes tokens)
	encodedToken := base64.RawURLEncoding.EncodeToString([]byte("test-token"))
	req := httptest.NewRequest(http.MethodGet, "/d/abc123", nil)
	req.Header.Set("Authorization", "Bearer "+encodedToken)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Check Cache-Control header
	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl != "max-age=31536000, immutable" {
		t.Errorf("expected Cache-Control 'max-age=31536000, immutable', got %q", cacheControl)
	}

	// Check Content-Type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}

	// Authenticated discovery returns both auth config and match patterns.
	body := w.Body.String()
	expected := `{"auth":{"type":"oidc","issuer":"https://example.com","client_id":"test"},"matchPatterns":["*.example.com","prod-*"]}`
	if body != expected {
		t.Errorf("unexpected response body:\ngot:      %s\nexpected: %s", body, expected)
	}
}

func TestDiscoveryHandler_MissingAuthHeader(t *testing.T) {
	validator := &mockValidator{}
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: []string{"*.example.com"},
		AuthHash:      "abc123",
		UnauthHash:    "xyz789",
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	req := httptest.NewRequest(http.MethodGet, "/d/abc123", nil)
	// No Authorization header
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestDiscoveryHandler_InvalidToken(t *testing.T) {
	validator := &mockValidator{err: errors.New("invalid token")}
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: []string{"*.example.com"},
		AuthHash:      "abc123",
		UnauthHash:    "xyz789",
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	// Token must be base64url-encoded (as broker encodes tokens)
	encodedToken := base64.RawURLEncoding.EncodeToString([]byte("invalid-token"))
	req := httptest.NewRequest(http.MethodGet, "/d/abc123", nil)
	req.Header.Set("Authorization", "Bearer "+encodedToken)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestDiscoveryHandler_MethodNotAllowed(t *testing.T) {
	validator := &mockValidator{}
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: []string{"*.example.com"},
		AuthHash:      "abc123",
		UnauthHash:    "xyz789",
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	// Token must be base64url-encoded (as broker encodes tokens)
	encodedToken := base64.RawURLEncoding.EncodeToString([]byte("test-token"))
	req := httptest.NewRequest(http.MethodPost, "/d/abc123", nil)
	req.Header.Set("Authorization", "Bearer "+encodedToken)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestDiscoveryHandler_EmptyBearerToken(t *testing.T) {
	validator := &mockValidator{}
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: []string{"*.example.com"},
		AuthHash:      "abc123",
		UnauthHash:    "xyz789",
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	req := httptest.NewRequest(http.MethodGet, "/d/abc123", nil)
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestDiscoveryHandler_NonBearerAuth(t *testing.T) {
	validator := &mockValidator{}
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: []string{"*.example.com"},
		AuthHash:      "abc123",
		UnauthHash:    "xyz789",
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	req := httptest.NewRequest(http.MethodGet, "/d/abc123", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestDiscoveryHandler_EmptyPatterns(t *testing.T) {
	validator := &mockValidator{}
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: []string{},
		AuthHash:      "abc123",
		UnauthHash:    "xyz789",
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	// Token must be base64url-encoded (as broker encodes tokens)
	encodedToken := base64.RawURLEncoding.EncodeToString([]byte("test-token"))
	req := httptest.NewRequest(http.MethodGet, "/d/abc123", nil)
	req.Header.Set("Authorization", "Bearer "+encodedToken)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// With empty matchPatterns and omitempty, only auth is included.
	body := w.Body.String()
	if body != `{"auth":{"type":"oidc"}}` {
		t.Errorf("unexpected response body: %s", body)
	}
}

func TestDiscoveryRedirectHandler_UnauthWithoutAuthHeader(t *testing.T) {
	handler := policyserver.NewDiscoveryRedirectHandler("unauth123", "auth456", "")

	req := httptest.NewRequest(http.MethodGet, "/d/current", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	// Check status code is 302 Found (temporary redirect)
	if w.Code != http.StatusFound {
		t.Errorf("expected status 302, got %d", w.Code)
	}

	// Without Authorization header, should redirect to unauthHash.
	location := w.Header().Get("Location")
	if location != "/d/unauth123" {
		t.Errorf("expected Location '/d/unauth123', got %q", location)
	}

	// Check Cache-Control header is short-lived (5 minutes)
	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl != "max-age=300" {
		t.Errorf("expected Cache-Control 'max-age=300', got %q", cacheControl)
	}

	// Check Vary header so caches don't serve wrong response.
	vary := w.Header().Get("Vary")
	if vary != "Authorization" {
		t.Errorf("expected Vary 'Authorization', got %q", vary)
	}
}

func TestDiscoveryRedirectHandler_AuthWithAuthHeader(t *testing.T) {
	handler := policyserver.NewDiscoveryRedirectHandler("unauth123", "auth456", "")

	req := httptest.NewRequest(http.MethodGet, "/d/current", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()

	handler(w, req)

	// Check status code is 302 Found (temporary redirect)
	if w.Code != http.StatusFound {
		t.Errorf("expected status 302, got %d", w.Code)
	}

	// With Authorization header, should redirect to authHash.
	location := w.Header().Get("Location")
	if location != "/d/auth456" {
		t.Errorf("expected Location '/d/auth456', got %q", location)
	}

	// Check Vary header so caches don't serve wrong response.
	vary := w.Header().Get("Vary")
	if vary != "Authorization" {
		t.Errorf("expected Vary 'Authorization', got %q", vary)
	}
}

func TestDiscoveryRedirectHandler_WithBaseURL(t *testing.T) {
	handler := policyserver.NewDiscoveryRedirectHandler("unauth123", "auth456", "https://cdn.example.com")

	req := httptest.NewRequest(http.MethodGet, "/d/current", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	// Check status code is 302 Found (temporary redirect)
	if w.Code != http.StatusFound {
		t.Errorf("expected status 302, got %d", w.Code)
	}

	// Without auth header, should redirect to unauthHash with base URL.
	location := w.Header().Get("Location")
	if location != "https://cdn.example.com/d/unauth123" {
		t.Errorf("expected Location 'https://cdn.example.com/d/unauth123', got %q", location)
	}
}

func TestDiscoveryRedirectHandler_WithBaseURLAndAuth(t *testing.T) {
	handler := policyserver.NewDiscoveryRedirectHandler("unauth123", "auth456", "https://cdn.example.com")

	req := httptest.NewRequest(http.MethodGet, "/d/current", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()

	handler(w, req)

	// With auth header, should redirect to authHash with base URL.
	location := w.Header().Get("Location")
	if location != "https://cdn.example.com/d/auth456" {
		t.Errorf("expected Location 'https://cdn.example.com/d/auth456', got %q", location)
	}
}

func TestDiscoveryRedirectHandler_WithBaseURLTrailingSlash(t *testing.T) {
	handler := policyserver.NewDiscoveryRedirectHandler("unauth123", "auth456", "https://cdn.example.com/")

	req := httptest.NewRequest(http.MethodGet, "/d/current", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	// Check Location header correctly handles trailing slash
	location := w.Header().Get("Location")
	if location != "https://cdn.example.com/d/unauth123" {
		t.Errorf("expected Location 'https://cdn.example.com/d/unauth123', got %q", location)
	}
}

// Unauthenticated discovery tests

func TestUnauthDiscoveryHandler_Success(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{},
		MatchPatterns: []string{"*.example.com"},
		AuthHash:      "disc123",
		UnauthHash:    "boot456",
		AuthConfig: policyserver.BootstrapAuth{
			Type:     "oidc",
			Issuer:   "https://accounts.google.com",
			ClientID: "test-client-id",
			Scopes:   []string{"openid", "profile", "email"},
		},
	})

	// Request unauthenticated discovery endpoint - no auth required.
	req := httptest.NewRequest(http.MethodGet, "/d/boot456", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Check Cache-Control header
	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl != "max-age=31536000, immutable" {
		t.Errorf("expected Cache-Control 'max-age=31536000, immutable', got %q", cacheControl)
	}

	// Check body contains auth config in Discovery format.
	body := w.Body.String()
	expected := `{"auth":{"type":"oidc","issuer":"https://accounts.google.com","client_id":"test-client-id","scopes":["openid","profile","email"]}}`
	if body != expected {
		t.Errorf("unexpected response body:\ngot:      %s\nexpected: %s", body, expected)
	}
}

func TestUnauthDiscoveryHandler_NoAuthRequired(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{err: errors.New("this should not be called")},
		MatchPatterns: []string{"*.example.com"},
		AuthHash:      "disc123",
		UnauthHash:    "boot456",
		AuthConfig: policyserver.BootstrapAuth{
			Type:     "oidc",
			Issuer:   "https://example.com",
			ClientID: "client-id",
		},
	})

	// Unauthenticated discovery endpoint should work without Authorization header.
	req := httptest.NewRequest(http.MethodGet, "/d/boot456", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	// Should succeed even without auth.
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDiscoveryHandler_UnknownHash(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{},
		MatchPatterns: []string{"*.example.com"},
		AuthHash:      "disc123",
		UnauthHash:    "boot456",
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	// Request with unknown hash should return 404.
	req := httptest.NewRequest(http.MethodGet, "/d/unknown", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}
