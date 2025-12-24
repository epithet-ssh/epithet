package caclient_test

import (
	"bytes"
	"context"
	"errors"
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

func startCA() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
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
		PublicKey:  &pubKey,
		Connection: &conn,
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
			PublicKey:  &pubKey,
			Connection: &conn,
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
				PublicKey:  &pubKey,
				Connection: &conn,
			})

			require.Error(t, err)
			tt.checkErr(t, err)
		})
	}
}

func TestGetDiscovery_NoDiscoveryURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a hello request (empty body)
		body, _ := ioutil.ReadAll(r.Body)
		assert.Equal(t, "{}", string(body))
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	discovery, err := client.GetDiscovery(context.Background(), "test-token")
	assert.NoError(t, err)
	assert.Nil(t, discovery, "expected nil discovery when no Link header")
}

func TestGetDiscovery_WithDiscoveryURL(t *testing.T) {
	// Start discovery server first so we have its URL
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"matchPatterns": ["*.example.com", "*.test.local"]}`))
	}))
	defer discoveryServer.Close()

	// Start CA server that returns Link header pointing to discovery server
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+discoveryServer.URL+`>; rel="discovery"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	discovery, err := client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	require.NotNil(t, discovery)
	assert.Equal(t, []string{"*.example.com", "*.test.local"}, discovery.MatchPatterns)
}

func TestGetDiscovery_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid token"))
	}))
	defer server.Close()

	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	_, err = client.GetDiscovery(context.Background(), "bad-token")
	require.Error(t, err)

	var invalidToken *caclient.InvalidTokenError
	assert.True(t, errors.As(err, &invalidToken), "expected InvalidTokenError, got %T", err)
}

func TestGetDiscovery_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied"))
	}))
	defer server.Close()

	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	_, err = client.GetDiscovery(context.Background(), "test-token")
	require.Error(t, err)

	var policyDenied *caclient.PolicyDeniedError
	assert.True(t, errors.As(err, &policyDenied), "expected PolicyDeniedError, got %T", err)
}

func TestGetDiscovery_Failover(t *testing.T) {
	callCount := 0

	// First server returns 500, second returns 200
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	endpoints := []caclient.CAEndpoint{
		{URL: server1.URL, Priority: caclient.DefaultPriority},
		{URL: server2.URL, Priority: caclient.DefaultPriority - 1},
	}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	_, err = client.GetDiscovery(context.Background(), "test-token")
	assert.NoError(t, err)
	assert.Equal(t, 2, callCount, "should have tried both servers")
}

func TestGetCert_WithDiscoveryURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://discovery.example.com/d/abc123>; rel="discovery"`)
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
		PublicKey:  &pubKey,
		Connection: &conn,
	})

	require.NoError(t, err)
	assert.Equal(t, "https://discovery.example.com/d/abc123", resp.DiscoveryURL)
	assert.Equal(t, sshcert.RawCertificate("ssh-ed25519-cert-v01@openssh.com AAAA..."), resp.Certificate)
}

func TestGetDiscovery_HTTPCaching(t *testing.T) {
	discoveryCallCount := 0

	// Discovery server with Cache-Control header
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoveryCallCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300") // Cache for 5 minutes
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"matchPatterns": ["*.example.com"]}`))
	}))
	defer discoveryServer.Close()

	// CA server returns Link header pointing to discovery
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+discoveryServer.URL+`>; rel="discovery"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// First request should hit the discovery server
	discovery1, err := client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	require.NotNil(t, discovery1)
	assert.Equal(t, 1, discoveryCallCount, "first request should hit discovery server")

	// Second request should use cached response (same client)
	discovery2, err := client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	require.NotNil(t, discovery2)
	assert.Equal(t, 1, discoveryCallCount, "second request should use HTTP cache")

	// Results should be the same
	assert.Equal(t, discovery1.MatchPatterns, discovery2.MatchPatterns)
}

func TestGetDiscovery_HTTPCaching_NoCacheHeader(t *testing.T) {
	discoveryCallCount := 0

	// Discovery server WITHOUT Cache-Control header
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoveryCallCount++
		w.Header().Set("Content-Type", "application/json")
		// No Cache-Control header - should not be cached
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"matchPatterns": ["*.example.com"]}`))
	}))
	defer discoveryServer.Close()

	// CA server returns Link header pointing to discovery
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+discoveryServer.URL+`>; rel="discovery"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// First request
	_, err = client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, 1, discoveryCallCount)

	// Second request - without Cache-Control, should hit server again
	_, err = client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, 2, discoveryCallCount, "without Cache-Control, each request should hit the server")
}
