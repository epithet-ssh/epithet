package principal

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	// GeneratedHostSchemeV1 identifies a realm generated for one host by
	// default. The value is still a principal realm and may be copied only
	// when intentionally widening that authorization boundary.
	GeneratedHostSchemeV1 = "epithet-host-id-v1"

	generatedHostPrefixV1 = GeneratedHostSchemeV1 + ":"
	entropySize           = 32
	encodedSize           = (entropySize*8 + 5) / 6
	maxNamedLength        = 253
)

// Realm is the canonical, non-secret authorization boundary from which SSH
// certificate principals are derived. Its literal value is used byte-for-byte.
type Realm string

// GenerateHostRealm returns a collision-resistant realm in the namespace reserved
// for realms created implicitly during ordinary host enrollment.
func GenerateHostRealm() (Realm, error) {
	var entropy [entropySize]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generating host principal realm: %w", err)
	}
	return Realm(generatedHostPrefixV1 + base64.RawURLEncoding.EncodeToString(entropy[:])), nil
}

// ParseRealm validates a canonical human-readable or generated realm.
func ParseRealm(value string) (Realm, error) {
	switch {
	case strings.HasPrefix(value, GeneratedHostSchemeV1):
		return parseGeneratedHost(value)
	default:
		return parseNamed(value)
	}
}

// ParseNamedRealm validates a human-readable realm without changing its case.
func ParseNamedRealm(value string) (Realm, error) {
	realm, err := ParseRealm(value)
	if err != nil {
		return "", err
	}
	if realm.IsGeneratedHost() {
		return "", fmt.Errorf("realm %q uses a namespace reserved for generated host realms", value)
	}
	return realm, nil
}

func parseGeneratedHost(value string) (Realm, error) {
	if !strings.HasPrefix(value, generatedHostPrefixV1) {
		return "", fmt.Errorf("generated host realm must start with %q", generatedHostPrefixV1)
	}
	payload := strings.TrimPrefix(value, generatedHostPrefixV1)
	if len(payload) != encodedSize {
		return "", fmt.Errorf("generated host realm payload must be %d base64url characters", encodedSize)
	}
	entropy, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("decoding generated host realm payload: %w", err)
	}
	if len(entropy) != entropySize {
		return "", fmt.Errorf("generated host realm payload must decode to %d bytes", entropySize)
	}
	if base64.RawURLEncoding.EncodeToString(entropy) != payload {
		return "", fmt.Errorf("generated host realm payload is not canonical base64url")
	}
	return Realm(value), nil
}

func parseNamed(value string) (Realm, error) {
	if value == "" {
		return "", fmt.Errorf("realm is empty")
	}
	if len(value) > maxNamedLength {
		return "", fmt.Errorf("named realm exceeds %d bytes", maxNamedLength)
	}
	for i, b := range []byte(value) {
		if isASCIIAlphaNumeric(b) {
			continue
		}
		if i > 0 && i < len(value)-1 && (b == '-' || b == '_' || b == '.') {
			continue
		}
		return "", fmt.Errorf("named realm must use ASCII letters, digits, and internal '.', '_', or '-' characters")
	}
	return Realm(value), nil
}

func isASCIIAlphaNumeric(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// IsGeneratedHost reports whether the realm was generated for an individual
// host.
func (d Realm) IsGeneratedHost() bool {
	return strings.HasPrefix(string(d), generatedHostPrefixV1)
}

// String returns the canonical external representation of d.
func (d Realm) String() string {
	return string(d)
}

// Validate reports whether d is a canonical principal realm.
func (d Realm) Validate() error {
	_, err := ParseRealm(string(d))
	return err
}

// MarshalText implements encoding.TextMarshaler.
func (d Realm) MarshalText() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return []byte(d), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Realm) UnmarshalText(text []byte) error {
	parsed, err := ParseRealm(string(text))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
