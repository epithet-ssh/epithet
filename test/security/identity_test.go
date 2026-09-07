// SR-01 regression: exercise real OIDC verification, service authentication,
// inventory binding, Writ, and CA signing using only local TLS fixtures.
package security_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/inventorytest"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/writpolicy"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func trustServer(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tls-ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
	}), 0600))
	return path
}

func tlsconfigFor(t *testing.T, server *httptest.Server) tlsconfig.Config {
	t.Helper()
	return tlsconfig.Config{CACertFile: trustServer(t, server)}
}

func TestMappedIDControlsCertificateIssuance(t *testing.T) {
	for _, claim := range []string{"sub", "oid"} {
		t.Run(claim, func(t *testing.T) { testMappedIDIssuance(t, claim, oidc.StableID) })
	}
}

func TestEmailModesControlCertificateIssuance(t *testing.T) {
	t.Run("verified-email", func(t *testing.T) { testMappedIDIssuance(t, "", oidc.VerifiedEmail) })
	t.Run("email-override", func(t *testing.T) { testMappedIDIssuance(t, "email", oidc.StableID) })
}

func testMappedIDIssuance(t *testing.T, userIDClaim string, mode oidc.IdentityMode) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "review"))
	require.NoError(t, err)
	var issuer string
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "jwks_uri": issuer + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &key.PublicKey, KeyID: "review", Algorithm: "RS256", Use: "sig",
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)
	issuer = idp.URL

	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	invPath := filepath.Join(t.TempDir(), "inventory.yaml")
	inventoryYAML := `domains: [prod.example.com]
users:
  - userName: victim@example.com
    id: victim-subject
  - userName: inactive@example.com
    id: inactive@example.com
    active: false
hosts:
  - name: prod.example.com
    domain: prod.example.com
    principal-mode: epithet-principal-v1
    accounts: [root]
`
	emailMode := mode == oidc.VerifiedEmail || userIDClaim == "email"
	inventoryID := "victim-subject"
	if emailMode {
		inventoryID = "victim@example.com"
	}
	inventoryYAML = strings.ReplaceAll(inventoryYAML, "id: victim-subject", "id: "+inventoryID)
	require.NoError(t, os.WriteFile(invPath, []byte(inventoryYAML), 0600))
	inv, err := inventory.NewStatic([]string{invPath})
	require.NoError(t, err)
	pol, diags := writ.Load("allow id:\"" + inventoryID + "\" -> root@prod.example.com\nallow userName:\"inactive@example.com\" -> root@prod.example.com\n")
	require.NotNil(t, pol, "%v", diags)
	evaluator, _, err := writpolicy.New(pol, nil, writpolicy.Options{})
	require.NoError(t, err)
	is := inventorytest.ServeWithConfig(t, inv, oidc.Config{Issuer: issuer, ClientID: "review-client", IdentityMode: mode, UserIDClaim: userIDClaim, TLSConfig: tlsconfigFor(t, idp)}, pub)
	ph, err := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: pub, Evaluator: evaluator,
	})
	require.NoError(t, err)
	ps := httptest.NewTLSServer(ph)
	t.Cleanup(ps.Close)
	authority, err := ca.New(priv, ps.URL, ca.WithTLSConfig(tlsconfigFor(t, ps)), ca.WithInventory(is.URL, tlsconfigFor(t, is)))
	require.NoError(t, err)
	var issuanceLog bytes.Buffer
	certLogger := caserver.NewSlogCertLogger(slog.New(slog.NewJSONHandler(&issuanceLog, nil)))
	ch := caserver.New(authority, slog.New(slog.NewTextHandler(io.Discard, nil)), certLogger).Handler()
	attackerPub, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	requestBody, err := json.Marshal(caserver.CreateCertRequest{
		PublicKey:  attackerPub,
		Connection: policy.Connection{RemoteHost: "prod.example.com", RemoteUser: "root"},
	})
	require.NoError(t, err)
	for _, tc := range []struct {
		name, subject, email string
		verified             any
		status               int
	}{
		{"attacker-identity-control", "attacker-subject", "attacker@example.com", true, http.StatusForbidden},
		{"unverified-victim-email", "attacker-subject", "victim@example.com", false, http.StatusForbidden},
		{"verified-victim-email", "attacker-subject", "victim@example.com", true, http.StatusForbidden},
		{"missing-email-verification", "attacker-subject", "victim@example.com", nil, http.StatusForbidden},
		{"subject-matches-userName-only", "victim@example.com", "victim@example.com", true, http.StatusForbidden},
		{"missing-subject", "", "victim@example.com", true, http.StatusUnauthorized},
		{"bound-subject", "victim-subject", "victim@example.com", true, http.StatusOK},
		{"renamed-email", "victim-subject", "new-name@example.com", true, http.StatusOK},
		{"bound-subject-unverified-email", "victim-subject", "victim@example.com", false, http.StatusOK},
		{"bound-subject-no-email", "victim-subject", "", nil, http.StatusOK},
		{"email-case-differs", "attacker-subject", "Victim@example.com", true, http.StatusForbidden},
		{"inactive", "inactive@example.com", "inactive@example.com", true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuanceLog.Reset()
			if emailMode {
				switch {
				case tc.subject == "" || tc.email == "" || (mode == oidc.VerifiedEmail && tc.verified != true):
					tc.status = http.StatusUnauthorized
				case tc.email == inventoryID:
					tc.status = http.StatusOK
				default:
					tc.status = http.StatusForbidden
				}
			}
			claims := map[string]any{
				"iss": issuer, "aud": "review-client", "sub": tc.subject,
				"id":    "untrusted-token-id",
				"email": tc.email, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			}
			if !emailMode && userIDClaim != "sub" {
				claims[userIDClaim] = tc.subject
				if tc.subject != "" {
					claims["sub"] = "victim-subject" // Must not select this record when oid differs.
				}
			}
			if tc.email == "" {
				delete(claims, "email")
			}
			if tc.verified != nil {
				claims["email_verified"] = tc.verified
			}
			token, err := jwt.Signed(signer).Claims(claims).Serialize()
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "https://ca.example.test/", bytes.NewReader(requestBody))
			req.Header.Set("Authorization", "Bearer "+token)
			resp := httptest.NewRecorder()
			ch.ServeHTTP(resp, req)
			require.Equal(t, tc.status, resp.Code, "%s", resp.Body.String())
			if tc.status != http.StatusOK {
				require.Empty(t, issuanceLog.String())
				return
			}
			var entry map[string]any
			require.NoError(t, json.Unmarshal(issuanceLog.Bytes(), &entry))
			require.Equal(t, inventoryID, entry["id"])
			require.Equal(t, "victim@example.com", entry["userName"])
			require.NotContains(t, entry, "identity")
			require.NotContains(t, entry, "user_id")
			require.NotContains(t, issuanceLog.String(), token)
			require.NotContains(t, issuanceLog.String(), "untrusted-token-id")
			var issued caserver.CreateCertResponse
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &issued))
			parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.Certificate))
			require.NoError(t, err)
			cert, ok := parsed.(*ssh.Certificate)
			require.True(t, ok)
			expected, err := principal.DeriveV1(principal.Domain("prod.example.com"), "root")
			require.NoError(t, err)
			require.Equal(t, []string{expected}, cert.ValidPrincipals)
			require.Equal(t, "victim@example.com", cert.KeyId)
			checker := &ssh.CertChecker{}
			require.NoError(t, checker.CheckCert(expected, cert))
			require.Equal(t, string(pub), string(ssh.MarshalAuthorizedKey(cert.SignatureKey)))
		})
	}
}
