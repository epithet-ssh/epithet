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

func TestHello_Success(t *testing.T) {
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

	err = client.Hello(context.Background(), "test-token")
	assert.NoError(t, err)
}

func TestHello_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid token"))
	}))
	defer server.Close()

	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	err = client.Hello(context.Background(), "bad-token")
	require.Error(t, err)

	var invalidToken *caclient.InvalidTokenError
	assert.True(t, errors.As(err, &invalidToken), "expected InvalidTokenError, got %T", err)
}

func TestHello_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied"))
	}))
	defer server.Close()

	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	err = client.Hello(context.Background(), "test-token")
	require.Error(t, err)

	var policyDenied *caclient.PolicyDeniedError
	assert.True(t, errors.As(err, &policyDenied), "expected PolicyDeniedError, got %T", err)
}

func TestHello_Failover(t *testing.T) {
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

	err = client.Hello(context.Background(), "test-token")
	assert.NoError(t, err)
	assert.Equal(t, 2, callCount, "should have tried both servers")
}
