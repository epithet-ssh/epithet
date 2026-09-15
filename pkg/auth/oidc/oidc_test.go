package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// syncBuffer is a mutex-guarded byte buffer. Authenticate's out writer is
// written by performFullAuth's goroutine while this test's polling
// goroutine concurrently reads it to find the auth URL; bytes.Buffer isn't
// safe for that, so this stands in.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf...)
}

func TestAuthenticateCompletesCodeFlowViaAutoApprovingIdP(t *testing.T) {
	// performFullAuth would otherwise pop a real browser window on every
	// test run; stub the seam instead. The fake IdP is driven manually below.
	prevOpenBrowser := openBrowser
	openBrowser = func(string) error { return nil }
	t.Cleanup(func() { openBrowser = prevOpenBrowser })

	idp := oidctest.New(t)
	cfg := Config{IssuerURL: idp.Issuer(), ClientID: oidctest.ClientID}

	var out syncBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The flow prints "To authenticate, visit: <url>"; a goroutine plays the
	// browser by GETting that URL, which the fake IdP auto-approves.
	done := make(chan struct{})
	go func() {
		defer close(done)
		urlRe := regexp.MustCompile(`visit: (\S+)`)
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if m := urlRe.FindSubmatch(out.Bytes()); m != nil {
				resp, err := http.Get(string(m[1]))
				if err == nil {
					resp.Body.Close()
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	idToken, next, err := Authenticate(ctx, cfg, nil, &out)
	<-done
	require.NoError(t, err)
	require.NotEmpty(t, idToken)
	require.NotNil(t, next)
	require.Contains(t, idToken, ".") // it is a JWT
}

func TestAuthenticateReusesValidToken(t *testing.T) {
	idp := oidctest.New(t)
	cfg := Config{IssuerURL: idp.Issuer(), ClientID: oidctest.ClientID}
	prev := &oauth2.Token{AccessToken: "still-good", Expiry: time.Now().Add(time.Hour)}
	prev = prev.WithExtra(map[string]any{"id_token": idp.MintIDToken("x@y.z", time.Now().Add(time.Hour))})

	idToken, _, err := Authenticate(context.Background(), cfg, prev, io.Discard)
	require.NoError(t, err)
	require.NotEmpty(t, idToken)
}

func TestAuthenticateCompletesDeviceFlow(t *testing.T) {
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": server.URL, "authorization_endpoint": server.URL + "/auth",
			"device_authorization_endpoint": server.URL + "/device", "token_endpoint": server.URL + "/token",
			"jwks_uri": server.URL + "/keys", "response_types_supported": []string{"code"},
			"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "client", r.Form.Get("client_id"))
		require.Contains(t, r.Form.Get("scope"), "openid")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "device-code", "user_code": "ABCD-EFGH",
			"verification_uri": server.URL + "/activate", "expires_in": 30, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", r.Form.Get("grant_type"))
		require.Equal(t, "device-code", r.Form.Get("device_code"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access", "token_type": "Bearer", "expires_in": 300, "id_token": "header.payload.signature",
		})
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	idToken, next, err := Authenticate(ctx, Config{IssuerURL: server.URL, ClientID: "client", LoginMethod: LoginDevice}, nil, &out)
	require.NoError(t, err)
	require.Equal(t, "header.payload.signature", idToken)
	require.Equal(t, "access", next.AccessToken)
	require.Contains(t, out.String(), "To authenticate, visit: "+server.URL+"/activate")
	require.Contains(t, out.String(), "Enter code: ABCD-EFGH")
}

func TestDeviceLoginRequiresDiscoveryEndpoint(t *testing.T) {
	_, err := performDeviceAuth(context.Background(), oauth2.Config{}, io.Discard)
	require.ErrorIs(t, err, ErrDeviceAuthorizationUnsupported)
}
