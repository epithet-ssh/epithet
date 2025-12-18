package policyserver_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

// mockEvaluator is a simple test evaluator
type mockEvaluator struct {
	response *policyserver.Response
	err      error
}

func (m *mockEvaluator) Evaluate(token string, conn policy.Connection) (*policyserver.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

// encodeToken base64url encodes a token as the broker would
func encodeToken(token string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(token))
}

func TestHandler_Success(t *testing.T) {
	// Create a mock evaluator that approves requests
	evaluator := &mockEvaluator{
		response: &policyserver.Response{
			CertParams: ca.CertParams{
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
		Evaluator: evaluator,
	})

	// Create request (token is base64url encoded as the broker would send it)
	req := policyserver.Request{
		Token: encodeToken("test-token"),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp policyserver.Response
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
		Evaluator: evaluator,
	})

	req := policyserver.Request{
		Token: encodeToken("invalid-token"),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestHandler_Forbidden(t *testing.T) {
	evaluator := &mockEvaluator{
		err: policyserver.Forbidden("Access denied by policy"),
	}

	handler := policyserver.NewHandler(policyserver.Config{
		Evaluator: evaluator,
	})

	req := policyserver.Request{
		Token: encodeToken("valid-token"),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestHandler_NotHandled(t *testing.T) {
	evaluator := &mockEvaluator{
		err: policyserver.NotHandled("connection not handled by this policy server"),
	}

	handler := policyserver.NewHandler(policyserver.Config{
		Evaluator: evaluator,
	})

	req := policyserver.Request{
		Token: encodeToken("valid-token"),
		Connection: policy.Connection{
			RemoteHost: "unknown.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422, got %d", w.Code)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	evaluator := &mockEvaluator{}
	handler := policyserver.NewHandler(policyserver.Config{
		Evaluator: evaluator,
	})

	httpReq := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	evaluator := &mockEvaluator{}
	handler := policyserver.NewHandler(policyserver.Config{
		Evaluator: evaluator,
	})

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_InvalidTokenEncoding(t *testing.T) {
	evaluator := &mockEvaluator{}
	handler := policyserver.NewHandler(policyserver.Config{
		Evaluator: evaluator,
	})

	// Send a token that is not valid base64url
	req := policyserver.Request{
		Token: "!!!not-valid-base64!!!", // Invalid base64url characters
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("Invalid token encoding")) {
		t.Errorf("expected 'Invalid token encoding' in response, got %s", w.Body.String())
	}
}
