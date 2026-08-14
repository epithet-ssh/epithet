// Package serviceauth mints and verifies short-lived, request-bound JWTs
// that authenticate CA -> policy-server requests. It replaces RFC 9421 HTTP
// message signatures (pkg/httpsig): the CA signs a JWT per request instead
// of the request's HTTP fields, and the policy server verifies it against
// the CA's SSH public key.
package serviceauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// Audience is the aud claim on every service token.
const Audience = "epithet-policy"

// TokenTTL bounds how long a minted request token is accepted.
const TokenTTL = 60 * time.Second

// clockSkewGrace extends how far in the past iat may be beyond TokenTTL,
// absorbing clock drift between the CA and policy-server hosts.
const clockSkewGrace = 30 * time.Second

// requestClaims is the JWT payload minted per request. bh binds the token to
// a specific request body; htm/htu additionally bind it to the specific
// method and target (host+path) it was minted for, so a captured token
// can't be replayed against a different request that happens to carry the
// same (or empty) body — e.g. a GET / token replayed against a POST / with
// no body.
type requestClaims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	ID       string `json:"jti"`
	BodyHash string `json:"bh"`
	Method   string `json:"htm"`
	Target   string `json:"htu"`
}

// Signer mints request-bound JWTs signed with a CA SSH private key.
type Signer struct {
	signer      jose.Signer
	fingerprint string
}

// NewSigner creates a Signer from an SSH private key.
func NewSigner(privateKey sshcert.RawPrivateKey) (*Signer, error) {
	sshSigner, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}
	fingerprint := ssh.FingerprintSHA256(sshSigner.PublicKey())

	rawKey, err := ssh.ParseRawPrivateKey([]byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw private key: %w", err)
	}

	signingKey, alg, err := signParamsFor(rawKey)
	if err != nil {
		return nil, err
	}

	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signingKey}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT signer: %w", err)
	}

	return &Signer{signer: joseSigner, fingerprint: fingerprint}, nil
}

// Authorize mints a request-bound JWT and sets the Authorization header.
// body may be nil (GET); the bh claim is then over the empty string.
func (s *Signer) Authorize(req *http.Request, body []byte) error {
	return s.authorizeAt(req, body, time.Now())
}

// authorizeAt is Authorize with an injectable clock, so tests can mint an
// already-expired token without sleeping past TokenTTL.
func (s *Signer) authorizeAt(req *http.Request, body []byte, now time.Time) error {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return fmt.Errorf("failed to generate jti: %w", err)
	}

	sum := sha256.Sum256(body)

	claims := requestClaims{
		Issuer:   s.fingerprint,
		Audience: Audience,
		IssuedAt: now.Unix(),
		Expiry:   now.Add(TokenTTL).Unix(),
		ID:       hex.EncodeToString(jti),
		BodyHash: base64.RawURLEncoding.EncodeToString(sum[:]),
		Method:   req.Method,
		Target:   requestTarget(req.URL.Host, req.Host, req.URL.Path),
	}

	raw, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return fmt.Errorf("failed to sign request token: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+raw)
	return nil
}

// Verifier checks request-bound JWTs against the CA's SSH public key.
type Verifier struct {
	// key is a concrete crypto public key (ed25519.PublicKey, *rsa.PublicKey,
	// or *ecdsa.PublicKey); go-jose type-switches on it, so `any` is fine.
	key any
	alg jose.SignatureAlgorithm
}

// NewVerifier creates a Verifier from an SSH public key.
func NewVerifier(publicKey sshcert.RawPublicKey) (*Verifier, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key: %w", err)
	}
	cryptoKey := pubKey.(ssh.CryptoPublicKey).CryptoPublicKey()

	verifyKey, alg, err := verifyParamsFor(cryptoKey)
	if err != nil {
		return nil, err
	}

	return &Verifier{key: verifyKey, alg: alg}, nil
}

// Verify checks the request's Authorization header JWT: signature, aud,
// exp/iat freshness, that htm/htu match the request actually received, and
// that bh matches sha256(body). It takes the request (rather than just the
// header) because method/target binding needs req.Method, req.Host, and
// req.URL.Path.
func (v *Verifier) Verify(req *http.Request, body []byte) error {
	raw, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		return fmt.Errorf("missing or malformed Authorization header")
	}

	// Restrict parsing to the single expected algorithm so a token signed
	// with a weaker or unexpected alg can't be smuggled through.
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{v.alg})
	if err != nil {
		return fmt.Errorf("failed to parse request token: %w", err)
	}

	var claims requestClaims
	if err := token.Claims(v.key, &claims); err != nil {
		return fmt.Errorf("failed to verify request token: %w", err)
	}

	if claims.Audience != Audience {
		return fmt.Errorf("unexpected audience %q", claims.Audience)
	}

	now := time.Now()
	if !time.Unix(claims.Expiry, 0).After(now) {
		return fmt.Errorf("request token expired")
	}
	if time.Unix(claims.IssuedAt, 0).Before(now.Add(-(TokenTTL + clockSkewGrace))) {
		return fmt.Errorf("request token issued too long ago")
	}

	// A captured token is only valid for the exact request it was minted
	// for: same method, same target. Without this, a token minted for (say)
	// a bodyless GET could be replayed against any other bodyless request
	// within its 60s window, regardless of method or path.
	if claims.Method != req.Method {
		return fmt.Errorf("method mismatch")
	}
	// req.Host is authoritative for server-received requests (populated
	// from the Host header/request line by net/http); req.URL.Host is the
	// fallback so this also works against client-side *http.Request values
	// built with http.NewRequest, as our own tests do.
	if claims.Target != requestTarget(req.Host, req.URL.Host, req.URL.Path) {
		return fmt.Errorf("target mismatch")
	}

	sum := sha256.Sum256(body)
	expectedHash := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(claims.BodyHash), []byte(expectedHash)) != 1 {
		return fmt.Errorf("body hash mismatch")
	}

	return nil
}

// requestTarget normalizes a request's binding target as "host+path",
// preferring primary (req.URL.Host when signing, req.Host when verifying)
// and falling back to secondary when primary is empty. Mirrors how the old
// httpsig code derived @authority from whichever of req.Host/req.URL.Host
// was populated for a given *http.Request.
//
// An empty path is normalized to "/", matching net/url's own
// (*URL).RequestURI() behavior: Go's http.Client writes "GET / HTTP/1.1" on
// the wire even when req.URL.Path is "" (e.g. a policy URL configured
// without a trailing slash), so the signer must anticipate that
// normalization or its htu claim won't match what the server receives.
func requestTarget(primary, secondary, path string) string {
	host := primary
	if host == "" {
		host = secondary
	}
	if path == "" {
		path = "/"
	}
	return host + path
}

// signParamsFor maps a raw SSH private key to the key value and JWS
// algorithm go-jose needs to sign with it. This is the one part of
// httpsig's key-type switch that survives the RFC 9421 removal: go-jose
// still needs to know which alg matches a key's type/curve.
func signParamsFor(rawKey any) (signingKey any, alg jose.SignatureAlgorithm, err error) {
	switch key := rawKey.(type) {
	case *ed25519.PrivateKey:
		// go-jose wants the value type, ssh.ParseRawPrivateKey gives a pointer.
		return *key, jose.EdDSA, nil
	case ed25519.PrivateKey:
		return key, jose.EdDSA, nil
	case *rsa.PrivateKey:
		return key, jose.PS256, nil
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			return key, jose.ES256, nil
		case elliptic.P384():
			return key, jose.ES384, nil
		default:
			return nil, "", fmt.Errorf("unsupported ECDSA curve: %v", key.Curve.Params().Name)
		}
	default:
		return nil, "", fmt.Errorf("unsupported key type for signing: %T", rawKey)
	}
}

// verifyParamsFor maps a crypto public key (as returned by
// ssh.CryptoPublicKey().CryptoPublicKey()) to the key value and JWS
// algorithm used to verify it.
func verifyParamsFor(cryptoKey any) (verifyKey any, alg jose.SignatureAlgorithm, err error) {
	switch key := cryptoKey.(type) {
	case ed25519.PublicKey:
		return key, jose.EdDSA, nil
	case *rsa.PublicKey:
		return key, jose.PS256, nil
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return key, jose.ES256, nil
		case elliptic.P384():
			return key, jose.ES384, nil
		default:
			return nil, "", fmt.Errorf("unsupported ECDSA curve: %v", key.Curve.Params().Name)
		}
	default:
		return nil, "", fmt.Errorf("unsupported key type for verification: %T", cryptoKey)
	}
}
