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
		Hash:          "abc123",
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

	// Check body contains patterns
	body := w.Body.String()
	if body != `{"matchPatterns":["*.example.com","prod-*"]}` {
		t.Errorf("unexpected response body: %s", body)
	}
}

func TestDiscoveryHandler_MissingAuthHeader(t *testing.T) {
	validator := &mockValidator{}
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: []string{"*.example.com"},
		Hash:          "abc123",
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
		Hash:          "abc123",
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
		Hash:          "abc123",
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
		Hash:          "abc123",
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
		Hash:          "abc123",
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
		Hash:          "abc123",
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

	body := w.Body.String()
	if body != `{"matchPatterns":[]}` {
		t.Errorf("unexpected response body: %s", body)
	}
}
