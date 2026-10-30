package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/test/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercise CLI parsing, the Unix socket protocol, shared authentication, OIDC
// device authorization and polling, and verification of the resulting identity.
func TestAgentLoginDeviceFlow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method oidc.LoginMethod
		flag   string
	}{
		{"override browser default", oidc.LoginBrowser, "device"},
		{"use configured device default", oidc.LoginDevice, "auto"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t)
			var server *httptest.Server
			var deviceRequests, tokenRequests atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer": server.URL, "authorization_endpoint": server.URL + "/auth",
					"device_authorization_endpoint": server.URL + "/device", "token_endpoint": server.URL + "/token",
					"jwks_uri": idp.Issuer() + "/keys", "response_types_supported": []string{"code"},
					"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
				})
			})
			mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
				deviceRequests.Add(1)
				assert.NoError(t, r.ParseForm())
				assert.Equal(t, oidctest.ClientID, r.Form.Get("client_id"))
				assert.Contains(t, r.Form.Get("scope"), "openid")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"device_code": "device-code", "user_code": "ABCD-EFGH",
					"verification_uri": server.URL + "/activate", "expires_in": 30, "interval": 1,
				})
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				tokenRequests.Add(1)
				assert.NoError(t, r.ParseForm())
				assert.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", r.Form.Get("grant_type"))
				assert.Equal(t, "device-code", r.Form.Get("device_code"))
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "access", "token_type": "Bearer", "expires_in": 3600,
					"id_token": idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Hour), map[string]any{"iss": server.URL}),
				})
			})
			server = httptest.NewServer(mux)
			t.Cleanup(server.Close)

			dir, err := os.MkdirTemp("/tmp", "epithet-login-")
			require.NoError(t, err)
			t.Cleanup(func() { os.RemoveAll(dir) })
			socket := filepath.Join(dir, "b.sock")
			ca, err := caclient.New([]caclient.CAEndpoint{{URL: "https://ca.example"}})
			require.NoError(t, err)
			inventory, err := facts.NewAdminClient("", tlsconfig.Config{})
			require.NoError(t, err)
			cfg := oidc.LoginConfig{IssuerURL: server.URL, ClientID: oidctest.ClientID, LoginMethod: tc.method}
			b, err := broker.New(*slog.New(slog.NewTextHandler(io.Discard, nil)), socket,
				makeAgentTokenFactory(cfg, false), ca, "https://ca.example", inventory,
				makeAgentIdentityVerifier(wire.AuthConfig{Issuer: server.URL, ClientID: oidctest.ClientID}, tlsconfig.Config{}), filepath.Join(dir, "agents"))
			require.NoError(t, err)
			b.SetShutdownTimeout(0)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			done := make(chan error, 1)
			go func() { done <- b.Serve(ctx) }()
			t.Cleanup(func() {
				cancel()
				err := <-done
				if err != nil {
					require.ErrorIs(t, err, context.Canceled)
				}
			})
			select {
			case <-b.Ready():
			case <-ctx.Done():
				t.Fatal("broker did not become ready")
			}

			var command struct {
				Agent AgentCLI `cmd:""`
			}
			parser, err := kong.New(&command)
			require.NoError(t, err)
			_, err = parser.Parse([]string{"agent", "login", "--login-method=" + tc.flag})
			require.NoError(t, err)
			var out, progress bytes.Buffer
			require.NoError(t, command.Agent.Login.run(ctx, socket, &out, &progress, command.Agent.LoginMethod))
			require.Equal(t, "Logged in.\n", out.String())
			require.Contains(t, progress.String(), server.URL+"/activate")
			require.Contains(t, progress.String(), "ABCD-EFGH")

			// Identity uses the same cached login even when requesting another method.
			progress.Reset()
			identity, err := (brokerClient{socket: socket}).identity(ctx, &progress, "browser")
			require.NoError(t, err)
			require.Equal(t, "alice@example.com", identity.Email)
			require.Empty(t, progress.String())
			require.Equal(t, int32(1), deviceRequests.Load())
			require.Equal(t, int32(1), tokenRequests.Load())
		})
	}
}
