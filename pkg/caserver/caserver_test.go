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

func TestLinkHeaderPassthrough_RelativeURL(t *testing.T) {
	// Create a mock policy server that returns a relative Link header
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `</d/abc123def456>; rel="discovery"`)
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
	}))
	defer policyServer.Close()

	// Create CA and CA server
	_, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	logger := slog.Default()
	caHandler := caserver.New(caInstance, logger, nil, nil)
	caHTTPServer := httptest.NewServer(caHandler)
	defer caHTTPServer.Close()

	// Generate a test public key
	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	// Make a certificate request to the CA server
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

	// Verify the Link header is set with the resolved absolute URL
	link := resp.Header.Get("Link")
	// The policy server URL might be like http://127.0.0.1:12345
	// So the resolved URL should be http://127.0.0.1:12345/d/abc123def456
	require.Contains(t, link, "/d/abc123def456")
	require.Contains(t, link, `rel="discovery"`)
}

func TestLinkHeaderPassthrough_AbsoluteURL(t *testing.T) {
	// Create a mock policy server that returns an absolute Link header
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://discovery.example.com/d/xyz789>; rel="discovery"`)
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
	}))
	defer policyServer.Close()

	// Create CA and CA server
	_, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	logger := slog.Default()
	caHandler := caserver.New(caInstance, logger, nil, nil)
	caHTTPServer := httptest.NewServer(caHandler)
	defer caHTTPServer.Close()

	// Generate a test public key
	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	// Make a certificate request to the CA server
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

	// Verify the Link header is set with the absolute URL unchanged
	link := resp.Header.Get("Link")
	require.Equal(t, `<https://discovery.example.com/d/xyz789>; rel="discovery"`, link)
}

func TestLinkHeaderPassthrough_NoLinkHeader(t *testing.T) {
	// Create a mock policy server that doesn't set a Link header
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer policyServer.Close()

	// Create CA and CA server
	_, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	logger := slog.Default()
	caHandler := caserver.New(caInstance, logger, nil, nil)
	caHTTPServer := httptest.NewServer(caHandler)
	defer caHTTPServer.Close()

	// Generate a test public key
	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	// Make a certificate request to the CA server
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

	// Verify no Link header is set
	link := resp.Header.Get("Link")
	require.Empty(t, link)
}

func TestLinkHeaderPassthrough_OnPolicyError(t *testing.T) {
	// Create a mock policy server that returns 403 with a Link header
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `</d/forbidden123>; rel="discovery"`)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied by policy"))
	}))
	defer policyServer.Close()

	// Create CA and CA server
	_, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	logger := slog.Default()
	caHandler := caserver.New(caInstance, logger, nil, nil)
	caHTTPServer := httptest.NewServer(caHandler)
	defer caHTTPServer.Close()

	// Generate a test public key
	userPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	// Make a certificate request to the CA server
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

	// Verify the Link header is set even on error responses
	link := resp.Header.Get("Link")
	require.Contains(t, link, "/d/forbidden123")
	require.Contains(t, link, `rel="discovery"`)
}

func TestLinkHeaderPassthrough_HelloRequest(t *testing.T) {
	// Create a mock policy server that returns 200 with a Link header for hello requests
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `</d/hello789>; rel="discovery"`)
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
	}))
	defer policyServer.Close()

	// Create CA and CA server
	_, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	logger := slog.Default()
	caHandler := caserver.New(caInstance, logger, nil, nil)
	caHTTPServer := httptest.NewServer(caHandler)
	defer caHTTPServer.Close()

	// Make a hello request (empty body) to the CA server
	req, err := http.NewRequest("POST", caHTTPServer.URL, bytes.NewReader([]byte("{}")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify the Link header is set on hello response
	link := resp.Header.Get("Link")
	require.Contains(t, link, "/d/hello789")
	require.Contains(t, link, `rel="discovery"`)
}
