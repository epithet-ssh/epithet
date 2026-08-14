package policyserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

func TestHandler_GETDiscovery(t *testing.T) {
	discovery := &wire.Discovery{
		Auth: &wire.AuthConfig{
			Issuer:   "https://accounts.google.com",
			ClientID: "test-client-id",
		},
	}

	handler, sign := newHandler(t, policyserver.Config{
		// Validator is unused by the GET (discovery) path.
		Evaluator: &mockEvaluator{},
		Discovery: discovery,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sign(req, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var got wire.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if got.Auth.Issuer != "https://accounts.google.com" {
		t.Errorf("expected issuer 'https://accounts.google.com', got %q", got.Auth.Issuer)
	}
	if got.Auth.ClientID != "test-client-id" {
		t.Errorf("expected client_id 'test-client-id', got %q", got.Auth.ClientID)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "max-age=300" {
		t.Errorf("expected Cache-Control 'max-age=300', got %q", cc)
	}
}

func TestHandler_GETDiscovery_NotConfigured(t *testing.T) {
	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: &mockEvaluator{},
		// No Discovery configured.
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sign(req, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: &mockEvaluator{},
	})

	req := httptest.NewRequest(http.MethodPut, "/", nil)
	sign(req, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}
