// Package httpsig provides RFC 9421 HTTP Message Signature signing and
// verification using SSH keys. It bridges the SSH key types used by epithet
// with the yaronf/httpsign library.
package httpsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/yaronf/httpsign"
	"golang.org/x/crypto/ssh"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

const (
	// signatureExpiry is how long a signature is valid (seconds).
	signatureExpiry = 30

	// signatureName is the label used in Signature/Signature-Input headers.
	signatureName = "sig1"

	// verifyWindow allows some clock skew beyond the signature expiry.
	verifyWindow = 60 * time.Second

	// maxBodySize limits how much body the verifier reads for Content-Digest
	// validation. Prevents memory exhaustion from oversized requests.
	maxBodySize = 64 * 1024 // 64 KiB, generous for JSON policy requests.
)

// Signer signs HTTP requests using RFC 9421 with an SSH private key.
// It maintains separate internal signers for GET (no body) and POST
// (with content-digest) requests.
type Signer struct {
	getSigner  *httpsign.Signer
	postSigner *httpsign.Signer
	keyID      string
}

// NewSigner creates a Signer from an SSH private key.
func NewSigner(privateKey sshcert.RawPrivateKey) (*Signer, error) {
	sshSigner, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	keyID := ssh.FingerprintSHA256(sshSigner.PublicKey())

	rawKey, err := ssh.ParseRawPrivateKey([]byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw private key: %w", err)
	}

	getFields := httpsign.Headers("@method", "@path", "@authority")
	postFields := httpsign.Headers("@method", "@path", "@authority", "content-digest")

	getSigner, err := newCryptoSigner(rawKey, keyID, getFields)
	if err != nil {
		return nil, err
	}

	postSigner, err := newCryptoSigner(rawKey, keyID, postFields)
	if err != nil {
		return nil, err
	}

	return &Signer{
		getSigner:  getSigner,
		postSigner: postSigner,
		keyID:      keyID,
	}, nil
}

// KeyID returns the SSH public key fingerprint used as the signature key ID.
func (s *Signer) KeyID() string {
	return s.keyID
}

// SignRequest signs an HTTP request using RFC 9421. For requests with a body,
// it computes Content-Digest (SHA-256) first, then signs the request including
// the digest. Sets Signature, Signature-Input, and (for POST) Content-Digest headers.
func (s *Signer) SignRequest(req *http.Request) error {
	// Ensure req.Host is set so the httpsign library derives @authority
	// correctly. Go's HTTP client sends req.URL.Host as the Host header,
	// but req.Host is empty for client-created requests.
	if req.Host == "" && req.URL != nil {
		req.Host = req.URL.Host
	}

	var signer *httpsign.Signer
	if req.Body == nil || req.Method == http.MethodGet || req.Method == http.MethodHead {
		signer = s.getSigner
	} else {
		// Compute Content-Digest for requests with bodies.
		header, err := httpsign.GenerateContentDigestHeader(
			&req.Body,
			[]string{httpsign.DigestSha256},
		)
		if err != nil {
			return fmt.Errorf("failed to generate content digest: %w", err)
		}
		req.Header.Set("Content-Digest", header)
		signer = s.postSigner
	}

	sigInput, sig, err := httpsign.SignRequest(signatureName, *signer, req)
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}
	req.Header.Set("Signature", sig)
	req.Header.Set("Signature-Input", sigInput)
	return nil
}

// Verifier verifies RFC 9421 signatures on HTTP requests using an SSH public key.
type Verifier struct {
	getVerifier  *httpsign.Verifier
	postVerifier *httpsign.Verifier
}

// NewVerifier creates a Verifier from an SSH public key.
func NewVerifier(publicKey sshcert.RawPublicKey) (*Verifier, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key: %w", err)
	}

	keyID := ssh.FingerprintSHA256(pubKey)
	cryptoKey := pubKey.(ssh.CryptoPublicKey).CryptoPublicKey()

	getFields := httpsign.Headers("@method", "@path", "@authority")
	postFields := httpsign.Headers("@method", "@path", "@authority", "content-digest")

	getVerifier, err := newCryptoVerifier(cryptoKey, keyID, getFields)
	if err != nil {
		return nil, err
	}

	postVerifier, err := newCryptoVerifier(cryptoKey, keyID, postFields)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		getVerifier:  getVerifier,
		postVerifier: postVerifier,
	}, nil
}

// VerifyRequest verifies an HTTP request's RFC 9421 signature. For POST
// requests, also validates Content-Digest against the actual body.
func (v *Verifier) VerifyRequest(req *http.Request) error {
	var verifier *httpsign.Verifier
	if req.Body == nil || req.Method == http.MethodGet || req.Method == http.MethodHead {
		verifier = v.getVerifier
	} else {
		// Require Content-Digest on requests with bodies.
		received := req.Header.Values("Content-Digest")
		if len(received) == 0 {
			return fmt.Errorf("missing Content-Digest header on %s request", req.Method)
		}
		// Validate Content-Digest header against body before verifying signature.
		// MaxBodySize prevents unbounded memory consumption from oversized requests.
		err := httpsign.ValidateContentDigestHeader(
			received,
			&req.Body,
			[]string{httpsign.DigestSha256},
			httpsign.NewDigestOptions().SetMaxBodySize(maxBodySize),
		)
		if err != nil {
			return fmt.Errorf("content digest validation failed: %w", err)
		}
		verifier = v.postVerifier
	}

	return httpsign.VerifyRequest(signatureName, *verifier, req)
}

// newCryptoSigner creates an httpsign.Signer from a raw crypto key.
func newCryptoSigner(rawKey any, keyID string, fields httpsign.Fields) (*httpsign.Signer, error) {
	config := httpsign.NewSignConfig().
		SignCreated(true).
		SetKeyID(keyID).
		SetExpiresAfter(signatureExpiry)

	switch key := rawKey.(type) {
	case *ed25519.PrivateKey:
		return httpsign.NewEd25519Signer(*key, config, fields)
	case ed25519.PrivateKey:
		return httpsign.NewEd25519Signer(key, config, fields)
	case *rsa.PrivateKey:
		return httpsign.NewRSAPSSSigner(*key, config, fields)
	case *ecdsa.PrivateKey:
		return newECDSASigner(key, config, fields)
	default:
		return nil, fmt.Errorf("unsupported key type for signing: %T", rawKey)
	}
}

// newCryptoVerifier creates an httpsign.Verifier from a raw crypto key.
func newCryptoVerifier(cryptoKey any, keyID string, fields httpsign.Fields) (*httpsign.Verifier, error) {
	config := httpsign.NewVerifyConfig().
		SetKeyID(keyID).
		SetRejectExpired(true).
		SetNotOlderThan(verifyWindow)

	switch key := cryptoKey.(type) {
	case ed25519.PublicKey:
		return httpsign.NewEd25519Verifier(key, config, fields)
	case *rsa.PublicKey:
		return httpsign.NewRSAPSSVerifier(*key, config, fields)
	case *ecdsa.PublicKey:
		return newECDSAVerifier(key, config, fields)
	default:
		return nil, fmt.Errorf("unsupported key type for verification: %T", cryptoKey)
	}
}

// newECDSASigner creates an ECDSA signer, selecting P-256 or P-384 based on the key's curve.
func newECDSASigner(key *ecdsa.PrivateKey, config *httpsign.SignConfig, fields httpsign.Fields) (*httpsign.Signer, error) {
	switch key.Curve {
	case elliptic.P256():
		return httpsign.NewP256Signer(*key, config, fields)
	case elliptic.P384():
		return httpsign.NewP384Signer(*key, config, fields)
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %v", key.Curve.Params().Name)
	}
}

// newECDSAVerifier creates an ECDSA verifier, selecting P-256 or P-384 based on the key's curve.
func newECDSAVerifier(key *ecdsa.PublicKey, config *httpsign.VerifyConfig, fields httpsign.Fields) (*httpsign.Verifier, error) {
	switch key.Curve {
	case elliptic.P256():
		return httpsign.NewP256Verifier(*key, config, fields)
	case elliptic.P384():
		return httpsign.NewP384Verifier(*key, config, fields)
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %v", key.Curve.Params().Name)
	}
}
