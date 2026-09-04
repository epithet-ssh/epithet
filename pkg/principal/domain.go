package principal

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	// GeneratedHostSchemeV1 identifies a domain generated for one host by
	// default. The value is still a principal domain and may be copied only
	// when intentionally widening that authorization boundary.
	GeneratedHostSchemeV1 = "epithet-host-id-v1"

	generatedHostPrefixV1 = GeneratedHostSchemeV1 + ":"
	entropySize           = 32
	encodedSize           = (entropySize*8 + 5) / 6
	maxNamedLength        = 253
)

// Domain is the canonical, non-secret authorization boundary from which SSH
// certificate principals are derived. Its literal value is used byte-for-byte.
type Domain string

// GenerateHostDomain returns a collision-resistant domain in the namespace reserved
// for domains created implicitly during ordinary host enrollment.
func GenerateHostDomain() (Domain, error) {
	var entropy [entropySize]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generating host principal domain: %w", err)
	}
	return Domain(generatedHostPrefixV1 + base64.RawURLEncoding.EncodeToString(entropy[:])), nil
}

// ParseDomain validates a canonical human-readable or generated domain.
func ParseDomain(value string) (Domain, error) {
	switch {
	case strings.HasPrefix(value, GeneratedHostSchemeV1):
		return parseGeneratedHost(value)
	default:
		return parseNamed(value)
	}
}

// ParseNamedDomain validates an explicitly declared human-readable domain.
func ParseNamedDomain(value string) (Domain, error) {
	domain, err := ParseDomain(value)
	if err != nil {
		return "", err
	}
	if domain.IsGeneratedHost() {
		return "", fmt.Errorf("domain %q uses a namespace reserved for generated host domains", value)
	}
	return domain, nil
}

func parseGeneratedHost(value string) (Domain, error) {
	if !strings.HasPrefix(value, generatedHostPrefixV1) {
		return "", fmt.Errorf("generated host domain must start with %q", generatedHostPrefixV1)
	}
	payload := strings.TrimPrefix(value, generatedHostPrefixV1)
	if len(payload) != encodedSize {
		return "", fmt.Errorf("generated host domain payload must be %d base64url characters", encodedSize)
	}
	entropy, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("decoding generated host domain payload: %w", err)
	}
	if len(entropy) != entropySize {
		return "", fmt.Errorf("generated host domain payload must decode to %d bytes", entropySize)
	}
	if base64.RawURLEncoding.EncodeToString(entropy) != payload {
		return "", fmt.Errorf("generated host domain payload is not canonical base64url")
	}
	return Domain(value), nil
}

func parseNamed(value string) (Domain, error) {
	if value == "" {
		return "", fmt.Errorf("domain is empty")
	}
	if len(value) > maxNamedLength {
		return "", fmt.Errorf("named domain exceeds %d bytes", maxNamedLength)
	}
	for i, b := range []byte(value) {
		if isLowerAlphaNumeric(b) {
			continue
		}
		if i > 0 && i < len(value)-1 && (b == '-' || b == '_' || b == '.') {
			continue
		}
		return "", fmt.Errorf("named domain must use lowercase ASCII letters, digits, and internal '.', '_', or '-' characters")
	}
	return Domain(value), nil
}

func isLowerAlphaNumeric(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

// IsGeneratedHost reports whether the domain was generated for an individual
// host.
func (d Domain) IsGeneratedHost() bool {
	return strings.HasPrefix(string(d), generatedHostPrefixV1)
}

// String returns the canonical external representation of d.
func (d Domain) String() string {
	return string(d)
}

// Validate reports whether d is a canonical principal domain.
func (d Domain) Validate() error {
	_, err := ParseDomain(string(d))
	return err
}

// MarshalText implements encoding.TextMarshaler.
func (d Domain) MarshalText() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return []byte(d), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Domain) UnmarshalText(text []byte) error {
	parsed, err := ParseDomain(string(text))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
