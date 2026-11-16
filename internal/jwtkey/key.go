// Package jwtkey selects the JWT signature algorithm for an Epithet SSH key.
package jwtkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"
)

// VerificationKey pairs a public key with the only JWT algorithm accepted for it.
type VerificationKey struct {
	Public    crypto.PublicKey
	algorithm jose.SignatureAlgorithm
}

func ForPublicKey(public crypto.PublicKey) (VerificationKey, error) {
	var alg jose.SignatureAlgorithm
	switch key := public.(type) {
	case ed25519.PublicKey:
		alg = jose.EdDSA
	case *rsa.PublicKey:
		alg = jose.PS256
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			alg = jose.ES256
		case elliptic.P384():
			alg = jose.ES384
		default:
			return VerificationKey{}, fmt.Errorf("unsupported ECDSA curve: %s", key.Curve.Params().Name)
		}
	default:
		return VerificationKey{}, fmt.Errorf("unsupported JWT key type: %T", public)
	}
	return VerificationKey{Public: public, algorithm: alg}, nil
}

// Verify checks the signature before decoding claims. The caller validates their meaning.
func (k VerificationKey) Verify(raw string, claims any) error {
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{k.algorithm})
	if err != nil {
		return err
	}
	return token.Claims(k.Public, claims)
}

// NewSigner parses the configured SSH private key and derives its verification key.
func NewSigner(encoded sshcert.RawPrivateKey) (jose.Signer, VerificationKey, error) {
	raw, err := ssh.ParseRawPrivateKey([]byte(encoded))
	if err != nil {
		return nil, VerificationKey{}, fmt.Errorf("failed to parse SSH private key: %w", err)
	}
	// OpenSSH parsing returns a pointer for Ed25519. go-jose needs the value.
	if key, ok := raw.(*ed25519.PrivateKey); ok {
		raw = *key
	}
	private, ok := raw.(crypto.Signer)
	if !ok {
		return nil, VerificationKey{}, fmt.Errorf("unsupported JWT private key type: %T", raw)
	}
	key, err := ForPublicKey(private.Public())
	if err != nil {
		return nil, VerificationKey{}, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.algorithm, Key: private}, nil)
	if err != nil {
		return nil, VerificationKey{}, fmt.Errorf("failed to create JWT signer: %w", err)
	}
	return signer, key, nil
}
