package caserver_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestPublicPolicyErrorsKeepDiagnosticsPrivate(t *testing.T) {
	const private = "private policy rule finance-admin at /srv/private/policy.writ"
	for _, tc := range []struct {
		name         string
		status       int
		body         string
		publicStatus int
		publicBody   string
	}{
		{"denied", 403, private, 403, "access denied"},
		{"pending", 202, "waiting on manager-approval: " + private, 202, "authorization pending; try again later"},
		{"service credential", 401, private, 502, "CA dependency unavailable"},
		{"bad policy request", 400, private, 502, "CA dependency unavailable"},
		{"missing endpoint", 404, private, 502, "CA dependency unavailable"},
		{"legacy status", 422, private, 502, "CA dependency unavailable"},
		{"internal policy failure", 500, private, 502, "CA dependency unavailable"},
		{"unavailable policy", 503, private, 502, "CA dependency unavailable"},
		{"redirect", 302, private, 502, "CA dependency unavailable"},
		{"invalid response", 200, "not JSON", 502, "CA dependency unavailable"},
		{"invalid TTL", 200, `{"ttlSeconds":0}`, 502, "CA dependency unavailable"},
		{"expired authorization", 200, `{"ttlSeconds":300,"notAfter":"2000-01-01T00:00:00Z"}`, 502, "CA dependency unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			server, closeServer, token := newTestCAServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://private-policy.invalid/approval")
				w.Header().Set("Retry-After", "30")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}), logger)
			defer closeServer()
			pub, _, err := sshcert.GenerateKeys()
			require.NoError(t, err)
			body, err := json.Marshal(caserver.CreateCertRequest{PublicKey: pub, Connection: policy.Connection{RemoteHost: "host", RemoteUser: "root"}})
			require.NoError(t, err)
			r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			server.Config.Handler.ServeHTTP(w, r)
			require.Equal(t, tc.publicStatus, w.Code)
			require.Equal(t, tc.publicBody, w.Body.String())
			require.Equal(t, "text/plain", w.Header().Get("Content-Type"))
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Empty(t, w.Header().Get("Location"))
			require.Empty(t, w.Header().Get("Retry-After"))
			require.Contains(t, logs.String(), "certificate authorization failed")
			if tc.status != 200 {
				require.Contains(t, logs.String(), private)
			}
			require.NotContains(t, logs.String(), token)
		})
	}
}

func TestPublicDiscoveryErrorsKeepDiagnosticsPrivate(t *testing.T) {
	for _, status := range []int{200, 401, 403, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				fmt.Fprint(w, "private discovery diagnostic at /srv/private/inventory.yaml")
			}))
			defer upstream.Close()
			var logs bytes.Buffer
			server := caserver.New(newTestCAWithInventoryURL(t, upstream.URL), slog.New(slog.NewTextHandler(&logs, nil)), nil)
			w := httptest.NewRecorder()
			server.DiscoveryHandler().ServeHTTP(w, httptest.NewRequest("GET", "/discovery", nil))
			require.Equal(t, 502, w.Code)
			require.Equal(t, "CA dependency unavailable", w.Body.String())
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Contains(t, logs.String(), "failed to fetch discovery")
		})
	}
	t.Run("transport", func(t *testing.T) {
		upstream := httptest.NewServer(http.NotFoundHandler())
		upstream.Close()
		var logs bytes.Buffer
		server := caserver.New(newTestCAWithInventoryURL(t, upstream.URL), slog.New(slog.NewTextHandler(&logs, nil)), nil)
		w := httptest.NewRecorder()
		server.DiscoveryHandler().ServeHTTP(w, httptest.NewRequest("GET", "/discovery", nil))
		require.Equal(t, 502, w.Code)
		require.Equal(t, "CA dependency unavailable", w.Body.String())
		require.Contains(t, logs.String(), upstream.URL)
	})
}

func TestPublicInternalError(t *testing.T) {
	_, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	c, err := ca.New(priv, "https://private-policy.invalid") // No inventory configured.
	require.NoError(t, err)
	var logs bytes.Buffer
	server := caserver.New(c, slog.New(slog.NewTextHandler(&logs, nil)), nil)
	w := httptest.NewRecorder()
	server.DiscoveryHandler().ServeHTTP(w, httptest.NewRequest("GET", "/discovery", nil))
	require.Equal(t, 500, w.Code)
	require.Equal(t, "internal CA error", w.Body.String())
	require.Contains(t, logs.String(), "inventory service is required")
}

func TestPublicRequestErrorsAreFixed(t *testing.T) {
	server, closeServer, token := newTestCAServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ttlSeconds":300}`)
	}), slog.New(slog.DiscardHandler))
	defer closeServer()
	for _, tc := range []struct {
		name, body string
		noAuth     bool
		status     int
		message    string
	}{
		{"missing auth", `{}`, true, 401, "invalid or expired authentication"},
		{"invalid JSON", `{"connection":"private input"}`, false, 400, "invalid certificate request"},
		{"missing fields", `{}`, false, 400, "invalid certificate request"},
		{"missing account", `{"publicKey":"key","connection":{"remoteHost":"host"}}`, false, 400, "invalid certificate request"},
		{"invalid public key", `{"publicKey":"private input","connection":{"remoteHost":"host","remoteUser":"root"}}`, false, 400, "invalid certificate request"},
		{"oversized", strings.Repeat("x", wire.MaxBodySize+1), false, 413, "request too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
			if !tc.noAuth {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			w := httptest.NewRecorder()
			server.Config.Handler.ServeHTTP(w, r)
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, tc.message, w.Body.String())
		})
	}
}
