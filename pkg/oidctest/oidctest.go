// Package oidctest provides a minimal in-process OIDC provider for tests.
// It serves a discovery document, JWKS, an auto-approving authorization
// endpoint, and a token endpoint, and can mint signed ID tokens directly.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ClientID is the audience carried by every minted token.
const ClientID = "epithet-test-client"

// TokenEmail is the profile email minted by the /token endpoint (browser-flow path).
const TokenEmail = "test@example.com"

// Subject returns a deterministic test-only subject distinct from the email.
func Subject(email string) string { return "subject:" + email }

type IdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
}

func New(t *testing.T) *IdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	p := &IdP{key: key, signer: signer}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/keys", p.handleJWKS)
	mux.HandleFunc("/auth", p.handleAuth)
	mux.HandleFunc("/token", p.handleToken)

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *IdP) Issuer() string { return p.server.URL }

func (p *IdP) MintIDToken(email string, expiresAt time.Time) string {
	return p.MintIDTokenWithAudience(email, ClientID, expiresAt)
}

func (p *IdP) MintIDTokenWithAudience(email, aud string, expiresAt time.Time) string {
	return p.MintIDTokenWithClaims(email, expiresAt, map[string]any{"aud": aud})
}

// MintIDTokenWithClaims overrides standard fixture claims. A nil value removes
// a claim, allowing malformed tokens to exercise the real validation boundary.
func (p *IdP) MintIDTokenWithClaims(email string, expiresAt time.Time, overrides map[string]any) string {
	claims := map[string]any{
		"iss":            p.server.URL,
		"aud":            ClientID,
		"sub":            Subject(email),
		"email":          email,
		"email_verified": true,
		"iat":            time.Now().Unix(),
		"exp":            expiresAt.Unix(),
	}
	for name, value := range overrides {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}
	raw, err := jwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		panic(fmt.Sprintf("oidctest: mint token: %v", err))
	}
	return raw
}

func (p *IdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.server.URL,
		"authorization_endpoint":                p.server.URL + "/auth",
		"token_endpoint":                        p.server.URL + "/token",
		"jwks_uri":                              p.server.URL + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *IdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: p.key.Public(), KeyID: "test-key", Algorithm: "RS256", Use: "sig",
	}}}
	writeJSON(w, jwks)
}

// handleAuth auto-approves: it redirects straight back to the client's
// redirect_uri with a fixed code, echoing state. This is what makes the real
// authorization-code flow completable without a browser or a human.
func (p *IdP) handleAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect+"?code=test-code&state="+q.Get("state"), http.StatusFound)
}

func (p *IdP) handleToken(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"access_token":  "test-access-token",
		"token_type":    "Bearer",
		"refresh_token": "test-refresh-token",
		"expires_in":    300,
		"id_token":      p.MintIDToken(TokenEmail, time.Now().Add(5*time.Minute)),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
