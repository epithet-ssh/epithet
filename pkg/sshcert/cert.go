package sshcert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// RawPrivateKey is a private key in the on-disk private key format
type RawPrivateKey string

// RawCertificate is a cert in the on-disk certificate format
type RawCertificate string

// RawPublicKey is a public key in the on-disk format
type RawPublicKey string

// ParsePublicKey parses exactly one authorized-key-formatted SSH public key.
// Comments are accepted, but authorized_keys options, trailing records, and
// certificates are not. Callers that persist the key can use
// ssh.MarshalAuthorizedKey on the result to obtain its canonical form.
func ParsePublicKey(raw RawPublicKey) (ssh.PublicKey, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}
	if len(options) != 0 {
		return nil, fmt.Errorf("public key must not have authorized_keys options")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("public key input must contain exactly one key")
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return nil, fmt.Errorf("public key input is an SSH certificate, not a public key")
	}
	return key, nil
}

// Parse parses a certificate
func Parse(raw RawCertificate) (*ssh.Certificate, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("error certificate is not a certificate: %w", err)
	}
	return cert, nil
}

// Expiry extracts the expiration time from the certificate.
// Returns the ValidBefore time from the certificate, or an error if parsing fails.
func (r RawCertificate) Expiry() (time.Time, error) {
	cert, err := Parse(r)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// ValidBefore is a uint64 Unix timestamp
	return time.Unix(int64(cert.ValidBefore), 0), nil
}

// GenerateKeys generates a ed25519 keypair in on-disk format
func GenerateKeys() (RawPublicKey, RawPrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", "", err
	}

	pemKey, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return "", "", err
	}
	privateKey := pem.EncodeToMemory(pemKey)
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)

	return RawPublicKey(authorizedKey), RawPrivateKey(privateKey), nil
}
