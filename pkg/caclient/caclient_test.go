package caclient_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StubExample(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
	defer server.Close()

	client := server.Client()
	res, err := client.Post(server.URL, "application/json", bytes.NewBufferString(`{
		"pubkey":"hello",
		"token":"world"
	}`))
	require.NoError(err)

	body, err := ioutil.ReadAll(res.Body)
	require.NoError(err)

	assert.Equal("hello world", string(body))
}

func TestClient_422_ReturnsConnectionNotHandledError(t *testing.T) {
	// Create a test server that returns 422
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte("connection not handled by this CA"))
	}))
	defer server.Close()

	// Create a CA client pointing to our test server
	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Make a request
	pubKey := sshcert.RawPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB")
	conn := policy.Connection{
		RemoteHost: "unknown.example.com",
		RemoteUser: "user",
		Port:       22,
	}
	_, err = client.GetCert(context.Background(), "test-token", &caserver.CreateCertRequest{
		PublicKey:  pubKey,
		Connection: conn,
	})

	// Should return ConnectionNotHandledError
	require.Error(t, err)
	var connNotHandled *caclient.ConnectionNotHandledError
	require.True(t, errors.As(err, &connNotHandled), "expected ConnectionNotHandledError, got %T: %v", err, err)
	assert.Contains(t, connNotHandled.Message, "connection not handled")
}

func TestClient_422_DoesNotTripCircuitBreaker(t *testing.T) {
	callCount := 0

	// Create a test server that returns 422
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte("connection not handled"))
	}))
	defer server.Close()

	// Create a CA client
	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	pubKey := sshcert.RawPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB")
	conn := policy.Connection{
		RemoteHost: "unknown.example.com",
		RemoteUser: "user",
		Port:       22,
	}

	// Make multiple requests - circuit breaker should NOT trip
	for i := 0; i < 5; i++ {
		_, err = client.GetCert(context.Background(), "test-token", &caserver.CreateCertRequest{
			PublicKey:  pubKey,
			Connection: conn,
		})
		require.Error(t, err)

		var connNotHandled *caclient.ConnectionNotHandledError
		require.True(t, errors.As(err, &connNotHandled), "request %d: expected ConnectionNotHandledError, got %T", i+1, err)
	}

	// All 5 requests should have reached the server (circuit breaker not tripped)
	assert.Equal(t, 5, callCount, "expected 5 requests to reach server, but circuit breaker may have tripped")
}

func TestClient_StatusCodes(t *testing.T) {
	// Test 4xx status codes that don't trip circuit breaker
	// Note: 5xx responses trip the circuit breaker, which changes the error type,
	// so we test them separately in integration tests
	tests := []struct {
		name       string
		statusCode int
		checkErr   func(t *testing.T, err error)
	}{
		{
			"401 returns InvalidTokenError",
			http.StatusUnauthorized,
			func(t *testing.T, err error) {
				var e *caclient.InvalidTokenError
				assert.True(t, errors.As(err, &e), "expected InvalidTokenError, got %T", err)
			},
		},
		{
			"403 returns PolicyDeniedError",
			http.StatusForbidden,
			func(t *testing.T, err error) {
				var e *caclient.PolicyDeniedError
				assert.True(t, errors.As(err, &e), "expected PolicyDeniedError, got %T", err)
			},
		},
		{
			"422 returns ConnectionNotHandledError",
			http.StatusUnprocessableEntity,
			func(t *testing.T, err error) {
				var e *caclient.ConnectionNotHandledError
				assert.True(t, errors.As(err, &e), "expected ConnectionNotHandledError, got %T", err)
			},
		},
		{
			"400 returns InvalidRequestError",
			http.StatusBadRequest,
			func(t *testing.T, err error) {
				var e *caclient.InvalidRequestError
				assert.True(t, errors.As(err, &e), "expected InvalidRequestError, got %T", err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("test error message"))
			}))
			defer server.Close()

			endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
			client, err := caclient.New(endpoints)
			require.NoError(t, err)

			pubKey := sshcert.RawPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB")
			conn := policy.Connection{
				RemoteHost: "server.example.com",
				RemoteUser: "user",
				Port:       22,
			}
			_, err = client.GetCert(context.Background(), "test-token", &caserver.CreateCertRequest{
				PublicKey:  pubKey,
				Connection: conn,
			})

			require.Error(t, err)
			tt.checkErr(t, err)
		})
	}
}

func TestGetCert_ReturnsCertificateAndPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...", "policy": {"hostUsers": {"*.example.com": ["alice"]}}}`))
	}))
	defer server.Close()

	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	pubKey := sshcert.RawPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB")
	conn := policy.Connection{
		RemoteHost: "server.example.com",
		RemoteUser: "alice",
		Port:       22,
	}
	resp, err := client.GetCert(context.Background(), "test-token", &caserver.CreateCertRequest{
		PublicKey:  pubKey,
		Connection: conn,
	})

	require.NoError(t, err)
	assert.Equal(t, sshcert.RawCertificate("ssh-ed25519-cert-v01@openssh.com AAAA..."), resp.Certificate)
}

// Discovery flow tests

func TestGetDiscoveryHitsDiscoveryPathUnauthenticated(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"auth":{"issuer":"https://idp","client_id":"cid"}}`)
	}))
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: 0}})
	require.NoError(t, err)

	d, err := c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, "/discovery", gotPath)
	require.Empty(t, gotAuth, "discovery must be anonymous")
	require.Equal(t, "https://idp", d.Auth.Issuer)
}

func TestGetDiscovery_ServerError_ReturnsCAUnavailableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: caclient.DefaultPriority}})
	require.NoError(t, err)

	// With a single endpoint, a 5xx trips the circuit breaker on the first
	// attempt, so the pool reports AllCAsUnavailableError rather than the
	// underlying CAUnavailableError directly (same behavior GetCert has
	// always had for 5xx responses).
	_, err = c.GetDiscovery(context.Background())
	require.Error(t, err)
	var allUnavail *caclient.AllCAsUnavailableError
	require.True(t, errors.As(err, &allUnavail), "expected AllCAsUnavailableError, got %T: %v", err, err)
	assert.Contains(t, allUnavail.Message, "CA unavailable")
}

func TestGetDiscovery_ClientError_ReturnsInvalidRequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("nope"))
	}))
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: caclient.DefaultPriority}})
	require.NoError(t, err)

	_, err = c.GetDiscovery(context.Background())
	require.Error(t, err)
	var invalidReq *caclient.InvalidRequestError
	require.True(t, errors.As(err, &invalidReq), "expected InvalidRequestError, got %T: %v", err, err)
}

func TestGetPublicKey_ReturnsKey(t *testing.T) {
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... CA public key"))
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	pubKey, err := client.GetPublicKey(context.Background())
	require.NoError(t, err)
	assert.Contains(t, pubKey, "ssh-ed25519")
	assert.Contains(t, pubKey, "CA public key")
}

func TestGetPublicKey_HitsServerEachCall(t *testing.T) {
	callCount := 0
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."))
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	_, err = client.GetPublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	_, err = client.GetPublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}
