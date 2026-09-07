package policyserver_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

func TestHandler_MethodNotAllowed(t *testing.T) {
	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: &mockEvaluator{},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sign(req, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}
