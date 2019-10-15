package sshcert

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// RawPrivateKey is the raw on-disk private key format
type RawPrivateKey string

// RawCertificate is the raw on-disk certificate format
type RawCertificate string

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
