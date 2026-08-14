package policyserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

// newTestValidator builds a real validator against a fake IdP, so handler
// tests exercise the actual token-validation path rather than a stub.
func newTestValidator(t *testing.T) (*oidc.Validator, *oidctest.IdP) {
	t.Helper()
	idp := oidctest.New(t)
	v, err := oidc.NewValidator(context.Background(), oidc.Config{
		Issuer:   idp.Issuer(),
		ClientID: oidctest.ClientID,
	})
	require.NoError(t, err)
	return v, idp
}

// newHandler builds a policyserver handler configured with a freshly
// generated CA keypair, and returns a sign func that stamps requests the way
// the real CA does. Every handler test request must now be service-signed
// since NewHandler makes CAPublicKey (and therefore verification) required.
func newHandler(t *testing.T, config policyserver.Config) (http.Handler, func(*http.Request, []byte)) {
	t.Helper()
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	config.CAPublicKey = pub

	handler, err := policyserver.NewHandler(config)
	require.NoError(t, err)

	signer, err := serviceauth.NewSigner(priv)
	require.NoError(t, err)

	sign := func(req *http.Request, body []byte) {
		require.NoError(t, signer.Authorize(req, body))
	}
	return handler, sign
}

// mockEvaluator is a simple test evaluator.
type mockEvaluator struct {
	response *wire.PolicyResponse
	err      error
}

func (m *mockEvaluator) Evaluate(ctx context.Context, identity string, tokenExpiry time.Time, conn policy.Connection) (*wire.PolicyResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func TestHandler_Success(t *testing.T) {
	validator, idp := newTestValidator(t)
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
		},
	}

	handler, sign := newHandler(t, policyserver.Config{
		Validator: validator,
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: idp.MintIDToken("test@example.com", time.Now().Add(time.Minute)),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(httpReq, body)
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
	// Evaluator-forced 401: the token itself is valid, but the evaluator
	// rejects it (e.g. a policy-layer authentication concern). Confirms the
	// handler passes evaluator errors through unchanged.
	validator, idp := newTestValidator(t)
	evaluator := &mockEvaluator{
		err: &wire.PolicyError{StatusCode: http.StatusUnauthorized, Message: "Invalid token"},
	}

	handler, sign := newHandler(t, policyserver.Config{
		Validator: validator,
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: idp.MintIDToken("test@example.com", time.Now().Add(time.Minute)),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(httpReq, body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestHandler_InvalidToken(t *testing.T) {
	// Real 401 from the validator itself: an expired token must be rejected
	// before the evaluator ever runs.
	validator, idp := newTestValidator(t)
	evaluator := &mockEvaluator{}

	handler, sign := newHandler(t, policyserver.Config{
		Validator: validator,
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: idp.MintIDToken("test@example.com", time.Now().Add(-time.Minute)),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(httpReq, body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_Forbidden(t *testing.T) {
	validator, idp := newTestValidator(t)
	evaluator := &mockEvaluator{
		err: policyserver.Forbidden("Access denied by policy"),
	}

	handler, sign := newHandler(t, policyserver.Config{
		Validator: validator,
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: idp.MintIDToken("test@example.com", time.Now().Add(time.Minute)),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(httpReq, body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestHandler_NotHandled(t *testing.T) {
	validator, idp := newTestValidator(t)
	evaluator := &mockEvaluator{
		err: &wire.PolicyError{StatusCode: http.StatusUnprocessableEntity, Message: "connection not handled by this policy server"},
	}

	handler, sign := newHandler(t, policyserver.Config{
		Validator: validator,
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Token: idp.MintIDToken("test@example.com", time.Now().Add(time.Minute)),
		Connection: policy.Connection{
			RemoteHost: "unknown.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(httpReq, body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422, got %d", w.Code)
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	validator, _ := newTestValidator(t)
	handler, sign := newHandler(t, policyserver.Config{
		Validator: validator,
		Evaluator: &mockEvaluator{},
	})

	body := []byte("invalid json")
	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(httpReq, body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHandlerAcceptsBareToken(t *testing.T) {
	validator, idp := newTestValidator(t)
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
		},
	}

	handler, sign := newHandler(t, policyserver.Config{
		Validator: validator,
		Evaluator: evaluator,
	})

	token := idp.MintIDToken("alice@example.com", time.Now().Add(time.Minute))
	body, _ := json.Marshal(wire.PolicyRequest{Token: token})
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	sign(req, body)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNewHandler_RequiresCAPublicKey(t *testing.T) {
	// Verification is no longer optional: an empty CAPublicKey must fail
	// handler construction rather than silently skipping signature checks.
	_, err := policyserver.NewHandler(policyserver.Config{
		Evaluator: &mockEvaluator{},
	})
	require.Error(t, err)
}

func TestHandler_RejectsUnsignedRequest(t *testing.T) {
	handler, _ := newHandler(t, policyserver.Config{
		Evaluator: &mockEvaluator{},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOversizedRequestReportsTooLarge(t *testing.T) {
	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: &mockEvaluator{},
	})

	// Create a request body that exceeds MaxBodySize.
	big := bytes.Repeat([]byte("a"), wire.MaxBodySize+1)
	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(big))
	sign(httpReq, big)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httpReq)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.Contains(t, rec.Body.String(), "too large")
}
