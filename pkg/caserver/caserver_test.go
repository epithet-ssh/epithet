package caserver_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestURLStuff(t *testing.T) {
	base, err := url.Parse("https://epithet.io/")
	require.NoError(t, err)

	rel1, err := url.Parse("pubkey")
	require.NoError(t, err)

	abs := base.ResolveReference(rel1)

	assert.Equal(t, "https://epithet.io/pubkey", abs.String())
}

// newTestCAWithPolicyURL creates a CA instance pointed at the given policy
// server URL, generating a fresh CA keypair.
func newTestCAWithPolicyURL(t *testing.T, policyURL string) *ca.CA {
	t.Helper()

	_, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	caInstance, err := ca.New(caPrivateKey, policyURL)
	require.NoError(t, err)

	return caInstance
}

// newTestCAServer creates a CA server backed by a mock policy server for testing.
func newTestCAServer(t *testing.T, policyHandler http.Handler) (*httptest.Server, func()) {
	t.Helper()

	policyServer := httptest.NewServer(policyHandler)

	caInstance := newTestCAWithPolicyURL(t, policyServer.URL)

	logger := slog.Default()
	server := caserver.New(caInstance, logger, nil, nil)

	mux := http.NewServeMux()
	mux.Handle("/", server.Handler())
	mux.Handle("/discovery", server.DiscoveryHandler())

	caHTTPServer := httptest.NewServer(mux)

	cleanup := func() {
		caHTTPServer.Close()
		policyServer.Close()
	}

	return caHTTPServer, cleanup
}

// TestDiscoveryIsAnonymousPassThrough verifies GET /discovery is a plain,
// unauthenticated pass-through of the policy server's auth config — no
// token parsing, no probe request to the policy server, no Vary header.
func TestDiscoveryIsAnonymousPassThrough(t *testing.T) {
	// Stub policy server returning a slim discovery doc.
	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Cache-Control", "max-age=120")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"auth":{"issuer":"https://idp.example.com","client_id":"cid"}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer policySrv.Close()

	c := newTestCAWithPolicyURL(t, policySrv.URL)
	srv := caserver.New(c, slog.New(slog.DiscardHandler), nil, nil)

	req := httptest.NewRequest("GET", "/discovery", nil) // no Authorization header
	rec := httptest.NewRecorder()
	srv.DiscoveryHandler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "max-age=120", rec.Header().Get("Cache-Control"))
	var d wire.Discovery
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &d))
	require.Equal(t, "https://idp.example.com", d.Auth.Issuer)
	require.Empty(t, rec.Header().Get("Vary"))
}

// TestDiscoveryHandler_FallbackCacheControl verifies the 5-minute default is
// used when the policy server doesn't set Cache-Control.
func TestDiscoveryHandler_FallbackCacheControl(t *testing.T) {
	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"auth":{"issuer":"https://idp.example.com","client_id":"cid"}}`)
	}))
	defer policySrv.Close()

	c := newTestCAWithPolicyURL(t, policySrv.URL)
	srv := caserver.New(c, slog.New(slog.DiscardHandler), nil, nil)

	req := httptest.NewRequest("GET", "/discovery", nil)
	rec := httptest.NewRecorder()
	srv.DiscoveryHandler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "max-age=300", rec.Header().Get("Cache-Control"))
}

func TestGetPubKey(t *testing.T) {
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	caHTTPServer, cleanup := newTestCAServer(t, policyHandler)
	defer cleanup()

	resp, err := http.Get(caHTTPServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	// The Link header (and the /discovery it pointed to) is gone; clients
	// know the discovery path statically now.
	require.Empty(t, resp.Header.Get("Link"))
}

func TestCreateCert_Success(t *testing.T) {
	// Mock policy server that approves cert requests.
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := wire.PolicyResponse{
			CertParams: wire.CertParams{
				Identity:   "test-user",
				Names:      []string{"testuser"},
				Expiration: 5 * time.Minute,
				Extensions: map[string]string{"permit-pty": ""},
			},
			Policy: policy.Policy{
				HostUsers: map[string][]string{"*": {"testuser"}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	})

	caHTTPServer, cleanup := newTestCAServer(t, policyHandler)
	defer cleanup()

	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	certReq := caserver.CreateCertRequest{
		PublicKey: sshcert.RawPublicKey(userPubKey),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(certReq)

	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Link"))
}

func TestCreateCert_PolicyError(t *testing.T) {
	// Mock policy server that returns 403.
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied by policy"))
	})

	caHTTPServer, cleanup := newTestCAServer(t, policyHandler)
	defer cleanup()

	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	certReq := caserver.CreateCertRequest{
		PublicKey: sshcert.RawPublicKey(userPubKey),
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(certReq)

	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestCreateCert_MissingPublicKey(t *testing.T) {
	caHTTPServer, cleanup := newTestCAServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer cleanup()

	certReq := caserver.CreateCertRequest{
		Connection: policy.Connection{RemoteHost: "server.example.com", RemoteUser: "testuser", Port: 22},
	}
	body, _ := json.Marshal(certReq)

	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateCert_MissingConnection(t *testing.T) {
	caHTTPServer, cleanup := newTestCAServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer cleanup()

	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	certReq := caserver.CreateCertRequest{
		PublicKey: sshcert.RawPublicKey(userPubKey),
	}
	body, _ := json.Marshal(certReq)

	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateCert_EmptyBody(t *testing.T) {
	// The old hello shape (both fields absent) is gone: an empty body is
	// just a request missing both required fields, and gets a 400 like any
	// other incomplete request.
	caHTTPServer, cleanup := newTestCAServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer cleanup()

	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader([]byte("{}")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
