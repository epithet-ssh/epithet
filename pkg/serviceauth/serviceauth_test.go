package serviceauth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
)

func keyPair(t *testing.T) (sshcert.RawPublicKey, sshcert.RawPrivateKey) {
	t.Helper()
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	return pub, priv
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv := keyPair(t)
	s, err := NewSigner(priv)
	require.NoError(t, err)
	v, err := NewVerifier(pub)
	require.NoError(t, err)

	body := []byte(`{"token":"x"}`)
	req, _ := http.NewRequest("POST", "http://policy/", strings.NewReader(string(body)))
	require.NoError(t, s.Authorize(req, body))
	require.NoError(t, v.Verify(req, body))
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	pub, priv := keyPair(t)
	s, _ := NewSigner(priv)
	v, _ := NewVerifier(pub)
	req, _ := http.NewRequest("POST", "http://policy/", nil)
	require.NoError(t, s.Authorize(req, []byte("original")))
	require.Error(t, v.Verify(req, []byte("tampered")))
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := keyPair(t)
	otherPub, _ := keyPair(t)
	s, _ := NewSigner(priv)
	v, _ := NewVerifier(otherPub)
	req, _ := http.NewRequest("GET", "http://policy/", nil)
	require.NoError(t, s.Authorize(req, nil))
	require.Error(t, v.Verify(req, nil))
}

func TestVerifyRejectsMissingHeader(t *testing.T) {
	pub, _ := keyPair(t)
	v, err := NewVerifier(pub)
	require.NoError(t, err)
	req, _ := http.NewRequest("GET", "http://policy/", nil)
	require.Error(t, v.Verify(req, nil))
}

// TestVerifyRejectsExpiredToken mints a token whose iat/exp are already in
// the past by using authorizeAt directly, so the test doesn't need to sleep
// past TokenTTL to observe expiry rejection.
func TestVerifyRejectsExpiredToken(t *testing.T) {
	pub, priv := keyPair(t)
	s, err := NewSigner(priv)
	require.NoError(t, err)
	v, err := NewVerifier(pub)
	require.NoError(t, err)

	req, _ := http.NewRequest("GET", "http://policy/", nil)
	past := time.Now().Add(-2 * TokenTTL)
	require.NoError(t, s.authorizeAt(req, nil, past))
	require.Error(t, v.Verify(req, nil))
}

// TestVerifyRejectsMethodMismatch confirms a token minted for POST / can't
// be replayed against a GET / carrying the same (empty) body — the scenario
// the security review flagged: htm/htu binding closes what bh alone missed.
func TestVerifyRejectsMethodMismatch(t *testing.T) {
	pub, priv := keyPair(t)
	s, err := NewSigner(priv)
	require.NoError(t, err)
	v, err := NewVerifier(pub)
	require.NoError(t, err)

	postReq, _ := http.NewRequest("POST", "http://policy/", nil)
	require.NoError(t, s.Authorize(postReq, nil))

	// Simulate a captured token presented against a different request that
	// happens to share the same (empty) body.
	getReq, _ := http.NewRequest("GET", "http://policy/", nil)
	getReq.Header.Set("Authorization", postReq.Header.Get("Authorization"))

	require.Error(t, v.Verify(getReq, nil))
}

// TestVerifyRejectsTargetMismatch confirms a token minted for path /a can't
// be replayed against path /b.
func TestVerifyRejectsTargetMismatch(t *testing.T) {
	pub, priv := keyPair(t)
	s, err := NewSigner(priv)
	require.NoError(t, err)
	v, err := NewVerifier(pub)
	require.NoError(t, err)

	reqA, _ := http.NewRequest("GET", "http://policy/a", nil)
	require.NoError(t, s.Authorize(reqA, nil))

	reqB, _ := http.NewRequest("GET", "http://policy/b", nil)
	reqB.Header.Set("Authorization", reqA.Header.Get("Authorization"))

	require.Error(t, v.Verify(reqB, nil))
}
