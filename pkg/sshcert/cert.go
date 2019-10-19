package sshcert

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
)

// RawPrivateKey is a private key in the on-disk private key format
type RawPrivateKey string

// RawCertificate is a cert in the on-disk certificate format
type RawCertificate string

// RawPublicKey is a public key in the on-disk format
type RawPublicKey string

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

// GenerateKeys generates a ed25519 keypair in on-disk format
func GenerateKeys() (RawPublicKey, RawPrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}

	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", "", err
	}

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey),
	}
	privateKey := pem.EncodeToMemory(pemKey)
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)

	return RawPublicKey(authorizedKey), RawPrivateKey(privateKey), nil
}
