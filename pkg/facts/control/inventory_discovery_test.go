package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestInventoryDiscoveryAtArbitraryFactURL(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(public, serviceauth.InventoryAudience)
	require.NoError(t, err)
	token := "opaque+/=&?# 日本語"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		actor, err := verifier.VerifyActor(r, body)
		require.NoError(t, err)
		if r.URL.Path == "/tenant/facts" {
			require.Empty(t, actor)
			if r.Method == "GET" {
				require.Equal(t, "host", r.URL.Query().Get("host"))
				fmt.Fprint(w, `{"id":"h","name":["host"],"attributes":{},"accounts":null,"principal":{"mode":"account-name"}}`)
				return
			}
			require.Equal(t, "OPTIONS", r.Method)
			// Multiple links in one field: commas inside quoted templates are not separators.
			w.Header().Add("Link-Template", `"items{?id,after,limit,pending}"; rel="`+facts.InventoryRecordsRelation+`", "credentials{?token}"; rel="`+facts.InventoryTokensRelation+`", "events{?cursor,limit}"; rel="`+facts.InventoryAuditRelation+`"`)
			w.WriteHeader(204)
			return
		}
		require.Equal(t, "admin", actor)
		switch r.URL.Path {
		case "/tenant/items":
			require.Equal(t, "GET", r.Method)
			require.Equal(t, "opaque/id", r.URL.Query().Get("id"))
			w.Header().Set("ETag", `"9"`)
			json.NewEncoder(w).Encode(facts.InventoryRecord{ID: "opaque/id", Status: "pending", CreatedAt: time.Now(), UpdatedAt: time.Now()})
		case "/tenant/credentials":
			require.Equal(t, "DELETE", r.Method)
			require.Equal(t, token, r.URL.Query().Get("token"))
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected provider URL %s", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	cfg := tlsconfig.Config{Insecure: true}
	c, err := newProviderTestServer("", server.URL+"/tenant/facts", key, cfg)
	require.NoError(t, err)
	h, err := c.host(t.Context(), authorization{Actor: "admin"}, "opaque/id")
	require.NoError(t, err)
	require.EqualValues(t, 9, h.Revision)
	require.NoError(t, c.revokeToken(t.Context(), authorization{Actor: "admin"}, token))
	data, err := facts.NewDataClient("", server.URL+"/tenant/facts", key, cfg)
	require.NoError(t, err)
	host, err := data.Host(t.Context(), "host")
	require.NoError(t, err)
	require.NotNil(t, host)
}

func TestInventoryDiscoveryFallbackAndFailures(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	for _, status := range []int{200, 204, 400, 401, 403, 404, 405, 429, 499, 500, 503, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/facts", r.URL.Path)
				if r.Method == "OPTIONS" {
					w.WriteHeader(status)
					return
				}
				require.Equal(t, "GET", r.Method)
				fmt.Fprint(w, `{"id":"h","name":["host"],"accounts":null,"principal":{"mode":"account-name"}}`)
			}))
			defer server.Close()
			cfg := tlsconfig.Config{Insecure: true}
			c, err := newProviderTestServer("", server.URL+"/facts", key, cfg)
			require.NoError(t, err)
			caps, err := c.providerCapabilities(t.Context())
			if status >= 400 && status < 500 || status == 200 || status == 204 {
				require.NoError(t, err)
				require.NotContains(t, caps.Capabilities, "enroll")
			} else {
				require.ErrorIs(t, err, facts.ErrUnavailable)
			}
			data, err := facts.NewDataClient("", server.URL+"/facts", key, cfg)
			require.NoError(t, err)
			host, err := data.Host(t.Context(), "host")
			require.NoError(t, err)
			require.NotNil(t, host)
		})
	}
	for _, field := range []string{`not-a-string`, `"/items"; rel="` + facts.InventoryRecordsRelation + `"`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Link-Template", field)
			w.WriteHeader(204)
		}))
		c, err := newProviderTestServer("", server.URL, key, tlsconfig.Config{Insecure: true})
		require.NoError(t, err)
		_, err = c.providerCapabilities(t.Context())
		require.ErrorIs(t, err, facts.ErrUnavailable)
		server.Close()
	}
	// An operation-level 4xx is a rejection, not discovery fallback.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Link-Template", `"/items{/id}"; rel="`+facts.InventoryRecordsRelation+`", "/tokens{?token}"; rel="`+facts.InventoryTokensRelation+`", "/events"; rel="`+facts.InventoryAuditRelation+`"`)
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":"provider rejected operation"}`)
	}))
	defer server.Close()
	c, err := newProviderTestServer("", server.URL, key, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	_, err = c.createToken(t.Context(), authorization{Actor: "admin"}, 60)
	require.ErrorIs(t, err, facts.ErrDenied)
	require.ErrorContains(t, err, "provider rejected operation")
}
