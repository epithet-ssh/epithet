// Package serviceauth signs and verifies request-bound service credentials.
// It owns the JWT protocol shared by callers and fact providers.
package serviceauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/internal/jwtkey"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"
)

// Audience is the aud claim on every service token.
const Audience = "epithet-policy"
const InventoryAudience = "epithet-inventory"
const DirectoryAudience = "epithet-directory"

// TokenTTL bounds how long a minted request token is accepted.
const TokenTTL = 60 * time.Second

// clockSkewGrace extends how far in the past iat may be beyond TokenTTL,
// absorbing clock drift between service hosts.
const clockSkewGrace = 30 * time.Second

// requestClaims is the JWT payload minted per request. bh binds the token to
// a specific request body; htm/htu additionally bind it to the specific
// method and target (host, escaped path, and query) it was minted for, so a captured token
// can't be replayed against a different request that happens to carry the
// same (or empty) body — e.g. a GET / token replayed against a POST / with
// no body. if_match and content_type bind the write precondition and body interpretation.
type requestClaims struct {
	Subject     string `json:"sub,omitempty"`
	Issuer      string `json:"iss"`
	Audience    string `json:"aud"`
	IssuedAt    int64  `json:"iat"`
	Expiry      int64  `json:"exp"`
	ID          string `json:"jti"`
	BodyHash    string `json:"bh"`
	Method      string `json:"htm"`
	Target      string `json:"htu"`
	IfMatch     string `json:"if_match,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// Signer mints request-bound JWTs signed with a service SSH private key.
type Signer struct {
	signer      jose.Signer
	fingerprint string
	audience    string
}

// NewSigner creates a Signer from an SSH private key.
func NewSigner(privateKey sshcert.RawPrivateKey) (*Signer, error) {
	return NewSignerFor(privateKey, Audience)
}

func NewSignerFor(privateKey sshcert.RawPrivateKey, audience string) (*Signer, error) {
	if audience == "" {
		return nil, fmt.Errorf("service audience is required")
	}
	signer, key, err := jwtkey.NewSigner(privateKey)
	if err != nil {
		return nil, err
	}
	sshKey, err := ssh.NewPublicKey(key.Public)
	if err != nil {
		return nil, err
	}
	return &Signer{signer: signer, fingerprint: ssh.FingerprintSHA256(sshKey), audience: audience}, nil
}

// Authorize mints a request-bound JWT and sets the Authorization header.
// body may be nil (GET); the bh claim is then over the empty string.
func (s *Signer) Authorize(req *http.Request, body []byte) error {
	return s.authorizeAt(req, body, time.Now())
}

// AuthorizeActor binds the authenticated actor to this backend request.
// Control supplies an administrator identity or a verified enrollment subject.
func (s *Signer) AuthorizeActor(req *http.Request, body []byte, actor string) error {
	return s.authorizeActorAt(req, body, actor, time.Now())
}

// authorizeAt injects the clock for expiry tests.
func (s *Signer) authorizeAt(req *http.Request, body []byte, now time.Time) error {
	return s.authorizeActorAt(req, body, "", now)
}

func (s *Signer) authorizeActorAt(req *http.Request, body []byte, actor string, now time.Time) error {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return fmt.Errorf("failed to generate jti: %w", err)
	}

	sum := sha256.Sum256(body)

	claims := requestClaims{
		IfMatch:     req.Header.Get("If-Match"),
		ContentType: req.Header.Get("Content-Type"),
		Subject:     actor,
		Issuer:      s.fingerprint,
		Audience:    s.audience,
		IssuedAt:    now.Unix(),
		Expiry:      now.Add(TokenTTL).Unix(),
		ID:          hex.EncodeToString(jti),
		BodyHash:    base64.RawURLEncoding.EncodeToString(sum[:]),
		Method:      req.Method,
		Target:      requestTarget(req.Host, req.URL.Host, req.URL.RequestURI()),
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
	key      jwtkey.VerificationKey
	audience string
}

// NewVerifier creates a Verifier from an SSH public key.
func NewVerifier(publicKey sshcert.RawPublicKey) (*Verifier, error) {
	return NewVerifierFor(publicKey, Audience)
}

func NewVerifierFor(publicKey sshcert.RawPublicKey, audience string) (*Verifier, error) {
	if audience == "" {
		return nil, fmt.Errorf("service audience is required")
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key: %w", err)
	}
	cryptoKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported SSH public key type: %s", pubKey.Type())
	}
	key, err := jwtkey.ForPublicKey(cryptoKey.CryptoPublicKey())
	if err != nil {
		return nil, err
	}

	return &Verifier{key: key, audience: audience}, nil
}

// Verify checks the request's Authorization header JWT: signature, aud,
// exp/iat freshness, that htm/htu match the request actually received, and
// that bh matches sha256(body). It takes the request (rather than just the
// header) because method/target binding needs req.Method, req.Host, and
// req.URL.RequestURI().
func (v *Verifier) Verify(req *http.Request, body []byte) error {
	_, err := v.VerifyActor(req, body)
	return err
}

// VerifyActor returns only the subject covered by a valid request signature.
func (v *Verifier) VerifyActor(req *http.Request, body []byte) (string, error) {
	raw, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		return "", fmt.Errorf("missing or malformed Authorization header")
	}

	var claims requestClaims
	if err := v.key.Verify(raw, &claims); err != nil {
		return "", fmt.Errorf("failed to verify request token: %w", err)
	}

	if claims.Audience != v.audience {
		return "", fmt.Errorf("unexpected audience %q", claims.Audience)
	}

	now := time.Now()
	if !time.Unix(claims.Expiry, 0).After(now) {
		return "", fmt.Errorf("request token expired")
	}
	if time.Unix(claims.IssuedAt, 0).Before(now.Add(-(TokenTTL + clockSkewGrace))) {
		return "", fmt.Errorf("request token issued too long ago")
	}

	// A captured token is only valid for the exact request it was minted
	// for: same method, same target. Without this, a token minted for (say)
	// a bodyless GET could be replayed against any other bodyless request
	// within its 60s window, regardless of method or path.
	if claims.Method != req.Method {
		return "", fmt.Errorf("method mismatch")
	}
	// req.Host is authoritative for server-received requests (populated
	// from the Host header/request line by net/http); req.URL.Host is the
	// fallback so this also works against client-side *http.Request values
	// built with http.NewRequest, as our own tests do.
	if claims.Target != requestTarget(req.Host, req.URL.Host, req.URL.RequestURI()) {
		return "", fmt.Errorf("target mismatch")
	}

	if claims.ContentType != req.Header.Get("Content-Type") {
		return "", fmt.Errorf("Content-Type mismatch")
	}
	if claims.IfMatch != req.Header.Get("If-Match") {
		return "", fmt.Errorf("If-Match mismatch")
	}
	sum := sha256.Sum256(body)
	expectedHash := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(claims.BodyHash), []byte(expectedHash)) != 1 {
		return "", fmt.Errorf("body hash mismatch")
	}

	return claims.Subject, nil
}

// requestTarget normalizes a request's binding target as "host+escaped-path+query",
// preferring primary (req.Host)
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
