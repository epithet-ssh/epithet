package policyserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

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
	calls    int
	response *wire.PolicyResponse
	err      error
}

func (m *mockEvaluator) Evaluate(ctx context.Context, identity string, authExpiry time.Time, conn policy.Connection, facts *inventoryapi.Resolution) (*wire.PolicyResponse, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func TestHandler_Success(t *testing.T) {
	evaluator := &mockEvaluator{
		response: &wire.PolicyResponse{
			TTL:        5 * time.Minute,
			Extensions: map[string]string{"permit-pty": ""},
		},
	}

	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	req.Facts = &inventoryapi.Resolution{Version: 1, ResolvedAt: time.Now(), Authentication: inventoryapi.Authentication{ID: "test-id", ExpiresAt: time.Now().Add(time.Minute)}, Host: req.Connection.RemoteHost, Directory: inventoryapi.DirectorySnapshot{Revision: "d1"}, Inventory: inventoryapi.HostSnapshot{Revision: "h1"}}
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

	require.Equal(t, 5*time.Minute, resp.TTL)
	require.Equal(t, map[string]string{"permit-pty": ""}, resp.Extensions)
}

func TestHandler_Unauthorized(t *testing.T) {
	// Evaluator-forced 401: the token itself is valid, but the evaluator
	// rejects it (e.g. a policy-layer authentication concern). Confirms the
	// handler passes evaluator errors through unchanged.
	evaluator := &mockEvaluator{
		err: &wire.PolicyError{StatusCode: http.StatusUnauthorized, Message: "Invalid token"},
	}

	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	req.Facts = &inventoryapi.Resolution{Version: 1, ResolvedAt: time.Now(), Authentication: inventoryapi.Authentication{ID: "test-id", ExpiresAt: time.Now().Add(time.Minute)}, Host: req.Connection.RemoteHost, Directory: inventoryapi.DirectorySnapshot{Revision: "d1"}, Inventory: inventoryapi.HostSnapshot{Revision: "h1"}}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(httpReq, body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestHandler_ExpiredAuthentication(t *testing.T) {
	// Expired authentication facts must never reach evaluation.
	evaluator := &mockEvaluator{}

	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	req.Facts = &inventoryapi.Resolution{Version: 1, ResolvedAt: time.Now(), Authentication: inventoryapi.Authentication{ID: "test-id", ExpiresAt: time.Now().Add(-time.Minute)}, Host: req.Connection.RemoteHost, Directory: inventoryapi.DirectorySnapshot{Revision: "d1"}, Inventory: inventoryapi.HostSnapshot{Revision: "h1"}}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(httpReq, body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
	require.Zero(t, evaluator.calls)
}

func TestHandler_Forbidden(t *testing.T) {
	evaluator := &mockEvaluator{
		err: policyserver.Forbidden("Access denied by policy"),
	}

	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	req.Facts = &inventoryapi.Resolution{Version: 1, ResolvedAt: time.Now(), Authentication: inventoryapi.Authentication{ID: "test-id", ExpiresAt: time.Now().Add(time.Minute)}, Host: req.Connection.RemoteHost, Directory: inventoryapi.DirectorySnapshot{Revision: "d1"}, Inventory: inventoryapi.HostSnapshot{Revision: "h1"}}
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
	evaluator := &mockEvaluator{
		err: &wire.PolicyError{StatusCode: http.StatusUnprocessableEntity, Message: "connection not handled by this policy server"},
	}

	handler, sign := newHandler(t, policyserver.Config{
		Evaluator: evaluator,
	})

	req := wire.PolicyRequest{
		Connection: policy.Connection{
			RemoteHost: "unknown.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	req.Facts = &inventoryapi.Resolution{Version: 1, ResolvedAt: time.Now(), Authentication: inventoryapi.Authentication{ID: "test-id", ExpiresAt: time.Now().Add(time.Minute)}, Host: req.Connection.RemoteHost, Directory: inventoryapi.DirectorySnapshot{Revision: "d1"}, Inventory: inventoryapi.HostSnapshot{Revision: "h1"}}
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
	handler, sign := newHandler(t, policyserver.Config{
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

func TestHandlerRejectsBearerTokenField(t *testing.T) {
	evaluator := &mockEvaluator{}
	handler, sign := newHandler(t, policyserver.Config{Evaluator: evaluator})
	body := []byte(`{"token":"not-for-policy","connection":{"remote_host":"host"}}`)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	sign(req, body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, 400, rec.Code)
	require.Zero(t, evaluator.calls)
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

func TestPolicyRejectsMismatchedInventoryFacts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*wire.PolicyRequest)
	}{
		{"missing", func(r *wire.PolicyRequest) { r.Facts = nil }},
		{"different user", func(r *wire.PolicyRequest) { r.Facts.Authentication.ID = "mallory" }},
		{"expired authentication", func(r *wire.PolicyRequest) { r.Facts.Authentication.ExpiresAt = time.Now().Add(-time.Minute) }},
		{"missing authentication", func(r *wire.PolicyRequest) { r.Facts.Authentication = inventoryapi.Authentication{} }},
		{"different target", func(r *wire.PolicyRequest) { r.Facts.Host = "production" }},
		{"substituted record", func(r *wire.PolicyRequest) { r.Facts.Directory.User.ID = "mallory" }},
		{"missing active", func(r *wire.PolicyRequest) { r.Facts.Directory.User.Active = nil }},
		{"missing accounts", func(r *wire.PolicyRequest) { r.Facts.Inventory.Host.Resource.Accounts = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := &mockEvaluator{response: &wire.PolicyResponse{}}
			handler, sign := newHandler(t, policyserver.Config{Evaluator: evaluator})
			active := true
			auth := inventoryapi.Authentication{ID: "alice-id", ExpiresAt: time.Now().Add(time.Minute)}
			r := wire.PolicyRequest{Connection: policy.Connection{RemoteHost: "host"}, Facts: &inventoryapi.Resolution{Version: 1, Authentication: auth, Host: "host", ResolvedAt: time.Now(), Directory: inventoryapi.DirectorySnapshot{Revision: "d1", User: &inventoryapi.User{Schemas: []string{inventoryapi.UserSchema}, ID: auth.ID, UserName: "alice", Active: &active}}, Inventory: inventoryapi.HostSnapshot{Revision: "h1", Host: &inventoryapi.Host{Resource: inventoryapi.HostResource{Name: "host", Accounts: json.RawMessage(`null`)}, Principal: inventoryapi.Principal{Mode: "account-name"}}}}}
			tc.change(&r)
			body, err := json.Marshal(r)
			require.NoError(t, err)
			if tc.name == "missing accounts" {
				body = []byte(strings.Replace(string(body), `,"accounts":null`, "", 1))
			}
			req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
			sign(req, body)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			require.Equal(t, 400, w.Code, w.Body.String())
			require.Zero(t, evaluator.calls)
		})
	}
}
