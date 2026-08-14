package policyserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// mockValidator is a simple test token validator.
type mockValidator struct {
	identity string
	err      error
}

func (m *mockValidator) ValidateAndExtractIdentity(token string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if m.identity != "" {
		return m.identity, nil
	}
	return "test@example.com", nil
}

// mockEvaluator is a simple test evaluator.
type mockEvaluator struct {
	response *wire.PolicyResponse
	err      error
}

func (m *mockEvaluator) Evaluate(ctx context.Context, identity string, conn policy.Connection) (*wire.PolicyResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func TestHandler_Success(t *testing.T) {
	evaluator := &mockEvaluator{
		response: &wire.PolicyResponse{
			CertParams: wire.CertParams{
				Identity:   "test@example.com",
				Names:      []string{"testuser"},
				Expiration: 5 * time.Minute,
				Extensions: map[string]string{
					"permit-pty": "",
				},
			},
			Policy: policy.Policy{
				HostUsers: map[string][]string{
					"*": {"testuser"},
				},
			},
		},
	}

	handler := policyserver.NewHandler(policyserver.Config{
		Validator: &mockValidator{},
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: "test-token",
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp wire.PolicyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.CertParams.Identity != "test@example.com" {
		t.Errorf("expected identity 'test@example.com', got %q", resp.CertParams.Identity)
	}
}

func TestHandler_Unauthorized(t *testing.T) {
	evaluator := &mockEvaluator{
		err: policyserver.Unauthorized("Invalid token"),
	}

	handler := policyserver.NewHandler(policyserver.Config{
		Validator: &mockValidator{},
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: "invalid-token",
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestHandler_Forbidden(t *testing.T) {
	evaluator := &mockEvaluator{
		err: policyserver.Forbidden("Access denied by policy"),
	}

	handler := policyserver.NewHandler(policyserver.Config{
		Validator: &mockValidator{},
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: "valid-token",
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestHandler_NotHandled(t *testing.T) {
	evaluator := &mockEvaluator{
		err: policyserver.NotHandled("connection not handled by this policy server"),
	}

	handler := policyserver.NewHandler(policyserver.Config{
		Validator: &mockValidator{},
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: "valid-token",
		Connection: policy.Connection{
			RemoteHost: "unknown.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422, got %d", w.Code)
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	handler := policyserver.NewHandler(policyserver.Config{
		Validator: &mockValidator{},
		Evaluator: &mockEvaluator{},
	})

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHandlerAcceptsBareToken(t *testing.T) {
	evaluator := &mockEvaluator{
		response: &wire.PolicyResponse{
			CertParams: wire.CertParams{
				Identity:   "alice@example.com",
				Names:      []string{"alice"},
				Expiration: 5 * time.Minute,
				Extensions: map[string]string{
					"permit-pty": "",
				},
			},
			Policy: policy.Policy{
				HostUsers: map[string][]string{
					"*": {"alice"},
				},
			},
		},
	}

	handler := policyserver.NewHandler(policyserver.Config{
		Validator: &mockValidator{identity: "alice@example.com"},
		Evaluator: evaluator,
	})

	body, _ := json.Marshal(wire.PolicyRequest{Token: "raw.jwt.token"})
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
