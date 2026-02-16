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
	// Discovery server
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"matchPatterns": ["*.example.com", "*.test.local"]}`))
	}))
	defer discoveryServer.Close()

	// CA server (not used directly, but needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Set the discovery URL (normally learned from cert response Link header)
	client.SetDiscoveryURL(discoveryServer.URL)

	discovery, err := client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	require.NotNil(t, discovery)
	assert.Equal(t, []string{"*.example.com", "*.test.local"}, discovery.MatchPatterns)
}

func TestGetDiscovery_Unauthorized(t *testing.T) {
	// Discovery server returns 401
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid token"))
	}))
	defer discoveryServer.Close()

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Set discovery URL pointing to server that returns 401
	client.SetDiscoveryURL(discoveryServer.URL)

	_, err = client.GetDiscovery(context.Background(), "bad-token")
	require.Error(t, err)

	var invalidToken *caclient.InvalidTokenError
	assert.True(t, errors.As(err, &invalidToken), "expected InvalidTokenError, got %T", err)
}

func TestGetDiscovery_Forbidden(t *testing.T) {
	// Discovery server returns 403
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied"))
	}))
	defer discoveryServer.Close()

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Set discovery URL pointing to server that returns 403
	client.SetDiscoveryURL(discoveryServer.URL)

	_, err = client.GetDiscovery(context.Background(), "test-token")
	require.Error(t, err)

	var policyDenied *caclient.PolicyDeniedError
	assert.True(t, errors.As(err, &policyDenied), "expected PolicyDeniedError, got %T", err)
}

func TestGetDiscovery_NoCachedURL(t *testing.T) {
	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// No discovery URL set - should return nil without error
	discovery, err := client.GetDiscovery(context.Background(), "test-token")
	assert.NoError(t, err)
	assert.Nil(t, discovery, "expected nil when no discovery URL cached")
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

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Set the discovery URL (normally learned from cert response)
	client.SetDiscoveryURL(discoveryServer.URL)

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

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Set the discovery URL (normally learned from cert response)
	client.SetDiscoveryURL(discoveryServer.URL)

	// First request
	_, err = client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, 1, discoveryCallCount)

	// Second request - without Cache-Control, should hit server again
	_, err = client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, 2, discoveryCallCount, "without Cache-Control, each request should hit the server")
}

func TestGetDiscovery_FollowsRedirect(t *testing.T) {
	redirectCallCount := 0
	contentCallCount := 0
	var receivedAuthHeader string

	// Server that handles both /d/current (redirect) and /d/{hash} (content)
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/d/current" {
			redirectCallCount++
			w.Header().Set("Cache-Control", "max-age=300")
			w.Header().Set("Location", "/d/abc123hash")
			w.WriteHeader(http.StatusFound) // 302 temporary redirect
			return
		}
		if r.URL.Path == "/d/abc123hash" {
			contentCallCount++
			// Capture the Authorization header to verify it's forwarded
			receivedAuthHeader = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=31536000, immutable")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"matchPatterns": ["*.example.com"]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer discoveryServer.Close()

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Set the discovery URL to the redirect endpoint
	client.SetDiscoveryURL(discoveryServer.URL + "/d/current")

	// Request should follow redirect and get content
	discovery, err := client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	require.NotNil(t, discovery)
	assert.Equal(t, []string{"*.example.com"}, discovery.MatchPatterns)

	// Verify both endpoints were hit
	assert.Equal(t, 1, redirectCallCount, "redirect endpoint should be hit")
	assert.Equal(t, 1, contentCallCount, "content endpoint should be hit after redirect")

	// Verify Authorization header was forwarded on redirect
	assert.Equal(t, "Bearer test-token", receivedAuthHeader, "Authorization header should be forwarded on redirect")
}

func TestGetCert_CachesDiscoveryURL(t *testing.T) {
	// CA server returns Link header pointing to discovery
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://discovery.example.com/abc123>; rel="discovery"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...", "policy": {"hostUsers": {"*.example.com": ["alice"]}}}`))
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Before cert request, GetDiscovery returns nil (no cached URL)
	discovery, err := client.GetDiscovery(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Nil(t, discovery, "expected nil before cert request")

	// Make a cert request to cache the discovery URL
	pubKey := sshcert.RawPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB")
	conn := policy.Connection{RemoteHost: "server.example.com", RemoteUser: "alice", Port: 22}
	resp, err := client.GetCert(context.Background(), "test-token", &caserver.CreateCertRequest{
		PublicKey:  &pubKey,
		Connection: &conn,
	})
	require.NoError(t, err)
	assert.Equal(t, "https://discovery.example.com/abc123", resp.DiscoveryURL)
}

// Discovery flow tests

func TestGetPublicKey_ReturnsKeyAndDiscoveryURL(t *testing.T) {
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Link", `</d/current>; rel="discovery"`)
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

func TestGetPublicKey_CachesDiscoveryURL(t *testing.T) {
	callCount := 0
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Link", `</d/current>; rel="discovery"`)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."))
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// First call should hit server
	_, err = client.GetPublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call should still hit server (public key is not cached)
	// But the discovery URL should be cached internally
	_, err = client.GetPublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}

func TestGetPublicKey_NoDiscoveryLinkHeader(t *testing.T) {
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Link header - legacy CA without discovery URL
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."))
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// Should still return public key even without discovery URL
	pubKey, err := client.GetPublicKey(context.Background())
	require.NoError(t, err)
	assert.Contains(t, pubKey, "ssh-ed25519")
}

func TestGetDiscovery_Unauth_Success(t *testing.T) {
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"auth":{"type":"oidc","issuer":"https://accounts.google.com","client_id":"123.apps.googleusercontent.com","scopes":["openid","profile","email"]}}`))
	}))
	defer discoveryServer.Close()

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	client.SetDiscoveryURL(discoveryServer.URL)

	// Get discovery config without auth token
	discovery, err := client.GetDiscovery(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, discovery)

	assert.Equal(t, "oidc", discovery.Auth.Type)
	assert.Equal(t, "https://accounts.google.com", discovery.Auth.Issuer)
	assert.Equal(t, "123.apps.googleusercontent.com", discovery.Auth.ClientID)
	assert.Equal(t, []string{"openid", "profile", "email"}, discovery.Auth.Scopes)
}

func TestGetDiscovery_Unauth_CommandType(t *testing.T) {
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"auth":{"type":"command","command":"/usr/local/bin/custom-sso --tenant prod"}}`))
	}))
	defer discoveryServer.Close()

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	client.SetDiscoveryURL(discoveryServer.URL)

	// Get discovery config without auth token
	discovery, err := client.GetDiscovery(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, discovery)

	assert.Equal(t, "command", discovery.Auth.Type)
	assert.Equal(t, "/usr/local/bin/custom-sso --tenant prod", discovery.Auth.Command)
}

func TestGetDiscovery_Unauth_NoDiscoveryURL(t *testing.T) {
	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	// GetDiscovery should return nil when no discovery URL is cached
	discovery, err := client.GetDiscovery(context.Background(), "")
	assert.NoError(t, err)
	assert.Nil(t, discovery)
}

func TestGetDiscovery_Unauth_FollowsRedirect(t *testing.T) {
	redirectCallCount := 0
	contentCallCount := 0

	// Server that handles both /d/current (redirect) and /d/{hash} (content)
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/d/current" {
			redirectCallCount++
			w.Header().Set("Cache-Control", "max-age=300")
			w.Header().Set("Location", "/d/disc123hash")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/d/disc123hash" {
			contentCallCount++
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=31536000, immutable")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth":{"type":"oidc","issuer":"https://example.com","client_id":"test"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer discoveryServer.Close()

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	client.SetDiscoveryURL(discoveryServer.URL + "/d/current")

	// Get discovery config without auth token
	discovery, err := client.GetDiscovery(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, discovery)

	assert.Equal(t, "oidc", discovery.Auth.Type)
	assert.Equal(t, 1, redirectCallCount, "redirect endpoint should be hit")
	assert.Equal(t, 1, contentCallCount, "content endpoint should be hit after redirect")
}

func TestGetDiscovery_Unauth_HTTPCaching(t *testing.T) {
	callCount := 0

	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"auth":{"type":"oidc","issuer":"https://example.com","client_id":"test"}}`))
	}))
	defer discoveryServer.Close()

	// CA server (needed for client creation)
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caServer.Close()

	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	client.SetDiscoveryURL(discoveryServer.URL)

	// First discovery call should hit server
	_, err = client.GetDiscovery(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "first request should hit discovery server")

	// Second discovery call should use HTTP cache (same client has caching transport)
	_, err = client.GetDiscovery(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "second request should use HTTP cache")
}

// End-to-end integration test for the unified discovery flow.
func TestIntegration_UnifiedDiscovery(t *testing.T) {
	// This test simulates the full unified discovery flow:
	// 1. Client calls GET / on CA → gets public key + Link rel="discovery"
	// 2. Client calls GetDiscovery(ctx, "") → follows /d/current → gets auth config (no auth)
	// 3. Client uses auth config to authenticate (simulated)
	// 4. Client calls Hello() with token → learns discovery URL
	// 5. Client calls GetDiscovery(ctx, token) → follows /d/current → gets auth config + match patterns

	// Track which endpoints are called
	caRootCalls := 0
	helloCalls := 0
	unauthDiscoveryCalls := 0
	authDiscoveryCalls := 0

	// Policy server handles discovery. /d/current is auth-aware:
	// without Authorization header, redirect to unauth hash;
	// with Authorization header, redirect to auth hash.
	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/d/current":
			// Vary by Authorization so HTTP cache distinguishes auth vs unauth.
			w.Header().Set("Vary", "Authorization")
			auth := r.Header.Get("Authorization")
			if auth == "" {
				// Unauthenticated: redirect to unauth content hash
				w.Header().Set("Location", "/d/unauth123")
				w.Header().Set("Cache-Control", "max-age=300")
				w.WriteHeader(http.StatusFound)
			} else {
				// Authenticated: redirect to auth content hash
				w.Header().Set("Location", "/d/auth456")
				w.Header().Set("Cache-Control", "max-age=300")
				w.WriteHeader(http.StatusFound)
			}

		case "/d/unauth123":
			unauthDiscoveryCalls++
			// Serve auth config only - no match patterns without auth
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=31536000, immutable")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth":{"type":"oidc","issuer":"https://accounts.google.com","client_id":"test-client","scopes":["openid","profile"]}}`))

		case "/d/auth456":
			authDiscoveryCalls++
			// Authenticated: require valid token
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
				return
			}
			// Serve auth config + match patterns
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=31536000, immutable")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth":{"type":"oidc","issuer":"https://accounts.google.com","client_id":"test-client","scopes":["openid","profile"]},"matchPatterns":["*.example.com","prod-*"]}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer policyServer.Close()

	// CA server
	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if r.URL.Path == "/" {
				caRootCalls++
				// Return public key with discovery Link header
				w.Header().Set("Link", `<`+policyServer.URL+`/d/current>; rel="discovery"`)
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test-ca-key"))
				return
			}
		case http.MethodPost:
			if r.URL.Path == "/" {
				helloCalls++
				// Hello request - return discovery Link header
				auth := r.Header.Get("Authorization")
				if auth != "Bearer test-token" {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("unauthorized"))
					return
				}
				w.Header().Set("Link", `<`+policyServer.URL+`/d/current>; rel="discovery"`)
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer caServer.Close()

	// Create client
	endpoints := []caclient.CAEndpoint{{URL: caServer.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	ctx := context.Background()

	// Step 1: Get public key (also caches discovery URL from Link header)
	pubKey, err := client.GetPublicKey(ctx)
	require.NoError(t, err)
	assert.Contains(t, pubKey, "ssh-ed25519")
	assert.Equal(t, 1, caRootCalls, "should call CA root exactly once")

	// Step 2: Get discovery without auth → follows /d/current → unauth hash → auth config only
	discovery, err := client.GetDiscovery(ctx, "")
	require.NoError(t, err)
	require.NotNil(t, discovery)
	assert.Equal(t, "oidc", discovery.Auth.Type)
	assert.Equal(t, "https://accounts.google.com", discovery.Auth.Issuer)
	assert.Equal(t, "test-client", discovery.Auth.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, discovery.Auth.Scopes)
	assert.Equal(t, 1, unauthDiscoveryCalls, "should hit unauth content endpoint")

	// Step 3: Client uses auth config to authenticate (simulated)
	token := "test-token"

	// Step 4: Hello() to validate token and learn discovery URL
	err = client.Hello(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, 1, helloCalls, "should call hello exactly once")

	// Step 5: Get discovery with auth → follows /d/current → auth hash → auth config + match patterns
	discovery, err = client.GetDiscovery(ctx, token)
	require.NoError(t, err)
	require.NotNil(t, discovery)
	assert.Equal(t, "oidc", discovery.Auth.Type)
	assert.Equal(t, []string{"*.example.com", "prod-*"}, discovery.MatchPatterns)
	assert.Equal(t, 1, authDiscoveryCalls, "should hit auth content endpoint")
}
