package policyserver_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

func TestDiscoveryHandler_Unauthenticated(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{},
		MatchPatterns: []string{"*.example.com", "prod-*"},
		AuthConfig: policyserver.BootstrapAuth{
			Type:     "oidc",
			Issuer:   "https://accounts.google.com",
			ClientID: "test-client-id",
			Scopes:   []string{"openid", "profile", "email"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/discovery", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Unauthenticated: returns auth config only, no matchPatterns.
	body := w.Body.String()
	expected := `{"auth":{"type":"oidc","issuer":"https://accounts.google.com","client_id":"test-client-id","scopes":["openid","profile","email"]}}`
	if body != expected {
		t.Errorf("unexpected response body:\ngot:      %s\nexpected: %s", body, expected)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
	if vary := w.Header().Get("Vary"); vary != "Authorization" {
		t.Errorf("expected Vary 'Authorization', got %q", vary)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "max-age=300" {
		t.Errorf("expected Cache-Control 'max-age=300', got %q", cc)
	}
}

func TestDiscoveryHandler_Authenticated(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{},
		MatchPatterns: []string{"*.example.com", "prod-*"},
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc", Issuer: "https://example.com", ClientID: "test"},
	})

	encodedToken := base64.RawURLEncoding.EncodeToString([]byte("test-token"))
	req := httptest.NewRequest(http.MethodGet, "/discovery", nil)
	req.Header.Set("Authorization", "Bearer "+encodedToken)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Authenticated: returns auth config + matchPatterns.
	body := w.Body.String()
	expected := `{"auth":{"type":"oidc","issuer":"https://example.com","client_id":"test"},"matchPatterns":["*.example.com","prod-*"]}`
	if body != expected {
		t.Errorf("unexpected response body:\ngot:      %s\nexpected: %s", body, expected)
	}

	if vary := w.Header().Get("Vary"); vary != "Authorization" {
		t.Errorf("expected Vary 'Authorization', got %q", vary)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "max-age=300" {
		t.Errorf("expected Cache-Control 'max-age=300', got %q", cc)
	}
}

func TestDiscoveryHandler_InvalidToken(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{err: errors.New("invalid token")},
		MatchPatterns: []string{"*.example.com"},
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	encodedToken := base64.RawURLEncoding.EncodeToString([]byte("invalid-token"))
	req := httptest.NewRequest(http.MethodGet, "/discovery", nil)
	req.Header.Set("Authorization", "Bearer "+encodedToken)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestDiscoveryHandler_EmptyBearerToken(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{},
		MatchPatterns: []string{"*.example.com"},
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	req := httptest.NewRequest(http.MethodGet, "/discovery", nil)
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestDiscoveryHandler_NonBearerAuth(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{},
		MatchPatterns: []string{"*.example.com"},
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	req := httptest.NewRequest(http.MethodGet, "/discovery", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestDiscoveryHandler_MethodNotAllowed(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{},
		MatchPatterns: []string{"*.example.com"},
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	req := httptest.NewRequest(http.MethodPost, "/discovery", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestDiscoveryHandler_EmptyPatterns(t *testing.T) {
	handler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     &mockValidator{},
		MatchPatterns: []string{},
		AuthConfig:    policyserver.BootstrapAuth{Type: "oidc"},
	})

	encodedToken := base64.RawURLEncoding.EncodeToString([]byte("test-token"))
	req := httptest.NewRequest(http.MethodGet, "/discovery", nil)
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
