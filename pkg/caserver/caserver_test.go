package caserver_test

import (
	"bytes"
	"encoding/json"
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

// newTestCAServer creates a CA server backed by a mock policy server for testing.
func newTestCAServer(t *testing.T, policyHandler http.Handler) (*httptest.Server, func()) {
	t.Helper()

	policyServer := httptest.NewServer(policyHandler)

	_, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

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

func TestDiscoveryLinkHeader_OnCertResponse(t *testing.T) {
	// Mock policy server that approves cert requests.
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ca.PolicyResponse{
			CertParams: ca.CertParams{
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
		PublicKey: (*sshcert.RawPublicKey)(&userPubKey),
		Connection: &policy.Connection{
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

	// CA always sets the discovery Link header.
	link := resp.Header.Get("Link")
	require.Equal(t, `</discovery>; rel="discovery"`, link)
}

func TestDiscoveryLinkHeader_OnGetPubKey(t *testing.T) {
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	caHTTPServer, cleanup := newTestCAServer(t, policyHandler)
	defer cleanup()

	resp, err := http.Get(caHTTPServer.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Link header always present on public key response.
	link := resp.Header.Get("Link")
	require.Equal(t, `</discovery>; rel="discovery"`, link)
}

func TestDiscoveryLinkHeader_OnPolicyError(t *testing.T) {
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
		PublicKey: (*sshcert.RawPublicKey)(&userPubKey),
		Connection: &policy.Connection{
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

	// Link header present even on error responses.
	link := resp.Header.Get("Link")
	require.Equal(t, `</discovery>; rel="discovery"`, link)
}

func TestDiscoveryLinkHeader_OnHelloRequest(t *testing.T) {
	// Mock policy server that approves hello requests.
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ca.PolicyResponse{
			CertParams: ca.CertParams{
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

	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader([]byte("{}")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Link header present on hello response.
	link := resp.Header.Get("Link")
	require.Equal(t, `</discovery>; rel="discovery"`, link)
}
