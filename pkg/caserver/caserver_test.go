package caserver_test

import (
	"bytes"
	"encoding/json"
	"github.com/epithet-ssh/epithet/internal/catest"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/inventorytest"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

// newTestCAServer creates a CA server backed by a mock policy server for testing.
func newTestCAServer(t *testing.T, policyHandler http.Handler, loggers ...*slog.Logger) (*httptest.Server, func(), string) {
	t.Helper()

	idp := oidctest.New(t)
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	require.NoError(t, os.WriteFile(path, []byte("users:\n  - id: subject:test-user\n    userName: test-user\nhosts:\n  - pattern: \"**\"\n"), 0600))
	inv, err := inventory.NewStatic([]string{path})
	require.NoError(t, err)
	is := inventorytest.ServeFacts(t, inv, idp.Issuer(), pub)
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policyHandler.ServeHTTP(w, r)
	}))
	caInstance, err := ca.New(priv, catest.HTTPPolicy{URL: policyServer.URL, Key: priv, TLS: tlsconfig.Config{Insecure: true}}, is.CAOption())
	require.NoError(t, err)

	logger := slog.Default()
	if len(loggers) != 0 {
		logger = loggers[0]
	}
	server := caserver.New(caInstance, logger, nil)

	mux := http.NewServeMux()
	mux.Handle("/", server.Handler())
	mux.Handle("/discovery", server.DiscoveryHandler())

	caHTTPServer := httptest.NewServer(mux)

	cleanup := func() {
		caHTTPServer.Close()
		policyServer.Close()
	}

	return caHTTPServer, cleanup, idp.MintIDToken("test-user", time.Now().Add(time.Hour))
}

// Discovery uses local CA configuration even when both fact services are down.
func TestDiscoveryIsAnonymousAndIndependentOfFacts(t *testing.T) {
	idp := oidctest.New(t)
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	upstream := httptest.NewServer(http.NotFoundHandler())
	upstream.Close()
	auth := wire.AuthConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID}
	c, err := ca.New(key, nil, ca.WithFacts(upstream.URL, upstream.URL, oidc.Config{Issuer: auth.Issuer, ClientID: auth.ClientID}, auth, tlsconfig.Config{Insecure: true}))
	require.NoError(t, err)
	srv := caserver.New(c, slog.New(slog.DiscardHandler), nil)
	rec := httptest.NewRecorder()
	srv.DiscoveryHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/discovery", nil))
	require.Equal(t, 200, rec.Code)
	require.Equal(t, "max-age=300", rec.Header().Get("Cache-Control"))
	var d wire.Discovery
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &d))
	require.Equal(t, auth, *d.Auth)
	require.NotContains(t, rec.Body.String(), "identityMapping")
	require.Empty(t, rec.Header().Get("Vary"))
}

// TestGetPubKeyAdvertisesAuthLink verifies the CA points at its auth config
// with a relative Link target, so no client has to construct the path.
func TestGetPubKeyAdvertisesAuthLink(t *testing.T) {
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	caHTTPServer, cleanup, _ := newTestCAServer(t, policyHandler)
	defer cleanup()

	resp, err := http.Get(caHTTPServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t,
		`<discovery>; rel="https://epithet.dev/rel/auth"`,
		resp.Header.Get("Link"))
}

func TestGetPubKey(t *testing.T) {
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	caHTTPServer, cleanup, _ := newTestCAServer(t, policyHandler)
	defer cleanup()

	resp, err := http.Get(caHTTPServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	// The CA advertises its auth config with a relative Link target; clients
	// resolve it rather than knowing the path statically.
	require.Contains(t, resp.Header.Get("Link"), "https://epithet.dev/rel/auth")
}

func TestCreateCert_Success(t *testing.T) {
	// Mock policy server that approves cert requests.
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := wire.PolicyResponse{
			TTLSeconds: 300,
			Extensions: map[string]string{"permit-pty": ""},
		}
		json.NewEncoder(w).Encode(resp)
	})

	caHTTPServer, cleanup, token := newTestCAServer(t, policyHandler)
	defer cleanup()

	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	certReq := wire.CreateCertRequest{
		PublicKey: sshcert.RawPublicKey(userPubKey),
		Connection: wire.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(certReq)

	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Link"))
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &fields))
	require.Len(t, fields, 1)
	var cert sshcert.RawCertificate
	require.NoError(t, json.Unmarshal(fields["certificate"], &cert))
	_, err = sshcert.Parse(cert)
	require.NoError(t, err)
}

func TestCreateCert_PolicyError(t *testing.T) {
	// Mock policy server that returns 403.
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied by policy"))
	})

	caHTTPServer, cleanup, token := newTestCAServer(t, policyHandler)
	defer cleanup()

	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	certReq := wire.CreateCertRequest{
		PublicKey: sshcert.RawPublicKey(userPubKey),
		Connection: wire.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "testuser",
			Port:       22,
		},
	}
	body, _ := json.Marshal(certReq)

	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestCreateCert_MissingPublicKey(t *testing.T) {
	caHTTPServer, cleanup, _ := newTestCAServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer cleanup()

	certReq := wire.CreateCertRequest{
		Connection: wire.Connection{RemoteHost: "server.example.com", RemoteUser: "testuser", Port: 22},
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
	caHTTPServer, cleanup, _ := newTestCAServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer cleanup()

	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	certReq := wire.CreateCertRequest{
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
	caHTTPServer, cleanup, _ := newTestCAServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
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
