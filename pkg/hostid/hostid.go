// Package hostid defines Epithet's stable, non-secret host identifiers.
package hostid

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	// SchemeV1 identifies the first host-ID representation. It is part of the
	// canonical text stored on hosts and copied into inventory.
	SchemeV1 = "epithet-host-v1"

	entropySize = 32
	prefixV1    = SchemeV1 + "-"
	encodedSize = (entropySize*8 + 5) / 6
)

// ID is a canonical Epithet host identifier. It identifies a logical host but
// is neither secret nor an authentication credential.
type ID string

// Generate returns a new v1 host ID with 256 bits of operating-system
// randomness.
func Generate() (ID, error) {
	var entropy [entropySize]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generating host ID: %w", err)
	}
	return ID(prefixV1 + base64.RawURLEncoding.EncodeToString(entropy[:])), nil
}

// Parse validates canonical v1 host-ID text.
func Parse(value string) (ID, error) {
	if !strings.HasPrefix(value, prefixV1) {
		return "", fmt.Errorf("host ID must start with %q", prefixV1)
	}
	encoded := strings.TrimPrefix(value, prefixV1)
	if len(encoded) != encodedSize {
		return "", fmt.Errorf("host ID payload must be %d base64url characters", encodedSize)
	}
	entropy, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decoding host ID payload: %w", err)
	}
	if len(entropy) != entropySize {
		return "", fmt.Errorf("host ID payload must decode to %d bytes", entropySize)
	}
	if base64.RawURLEncoding.EncodeToString(entropy) != encoded {
		return "", fmt.Errorf("host ID payload is not canonical base64url")
	}
	return ID(value), nil
}

// String returns the canonical external representation of id.
func (id ID) String() string {
	return string(id)
}

// Validate reports whether id is a canonical host ID.
func (id ID) Validate() error {
	_, err := Parse(string(id))
	return err
}

// MarshalText implements encoding.TextMarshaler.
func (id ID) MarshalText() ([]byte, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return []byte(id), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *ID) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}
