//go:build securityreview

// These opt-in review probes assert observed vulnerable behavior, not desired
// behavior. When fixing a finding, replace its probe with a normal regression
// test that requires rejection. All keys, tokens, and servers are local fixtures.
package security_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestReviewHTTPSRedirectLeaksBearerAndTrustsPlaintextRoot(t *testing.T) {
	pub, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	seen := make(chan string, 1)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			seen <- r.Header.Get("Authorization")
			http.Error(w, "fixture", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, string(pub))
	}))
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(secure.Close)
	cfg := tlsconfigFor(t, secure)
	require.False(t, cfg.Insecure)
	require.NoError(t, cfg.ValidateURL(secure.URL))
	client, err := caclient.New([]caclient.CAEndpoint{{URL: secure.URL}}, caclient.WithTLSConfig(cfg))
	require.NoError(t, err)
	_, err = client.GetCert(context.Background(), "review-only-bearer", &caserver.CreateCertRequest{
		PublicKey: pub, Connection: policy.Connection{RemoteHost: "host", RemoteUser: "root"},
	})
	require.Error(t, err)
	select {
	case header := <-seen:
		require.Equal(t, "Bearer review-only-bearer", header)
	default:
		t.Fatal("probe did not observe the bearer on the plaintext destination")
	}
	root, err := client.GetRoot(context.Background())
	require.NoError(t, err)
	require.Equal(t, pub, root.PublicKey)
	require.Equal(t, plain.URL, root.FinalURL)
	t.Log("TLS verification enabled: bearer reached HTTP and bootstrap accepted a key returned over HTTP")
}

func TestReviewPolicyRedirectLeaksOIDCBody(t *testing.T) {
	seen := make(chan string, 1)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body wire.PolicyRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen <- body.Token
		http.Error(w, "fixture", http.StatusForbidden)
	}))
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(secure.Close)
	_, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	authority, err := ca.New(priv, secure.URL, ca.WithTLSConfig(tlsconfigFor(t, secure)))
	require.NoError(t, err)
	_, err = authority.RequestPolicy(context.Background(), "review-only-oidc-token", policy.Connection{})
	require.Error(t, err)
	select {
	case token := <-seen:
		require.Equal(t, "review-only-oidc-token", token)
	default:
		t.Fatal("probe did not observe the OIDC token on the plaintext destination")
	}
	t.Log("CA forwarded the OIDC token in the POST body across an HTTPS-to-HTTP redirect")
}
