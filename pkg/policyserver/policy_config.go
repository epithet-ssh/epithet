package policyserver

import (
	"fmt"
	"time"
)

// PolicyRulesConfig represents the policy server rules configuration.
// This defines users, hosts, and access policies - not CLI flags.
type PolicyRulesConfig struct {
	CAPublicKey string                 `yaml:"ca_pubkey" json:"ca_pubkey"`
	OIDC        OIDCConfig             `yaml:"oidc" json:"oidc"`
	Users       map[string][]string    `yaml:"users" json:"users"` // user identity → tags
	Defaults    *DefaultPolicy         `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Hosts       map[string]*HostPolicy `yaml:"hosts,omitempty" json:"hosts,omitempty"` // hostname → host policy
}

// OIDCConfig represents OIDC configuration for token validation
type OIDCConfig struct {
	Issuer   string `yaml:"issuer" json:"issuer"`
	Audience string `yaml:"audience" json:"audience"`
}

// DefaultPolicy defines default policy settings
type DefaultPolicy struct {
	Allow      map[string][]string `yaml:"allow,omitempty" json:"allow,omitempty"`           // principal → allowed tags
	Expiration string              `yaml:"expiration,omitempty" json:"expiration,omitempty"` // Default cert expiration (e.g., "5m")
	Extensions map[string]string   `yaml:"extensions,omitempty" json:"extensions,omitempty"` // Default cert extensions
}

// HostPolicy defines per-host policy overrides
type HostPolicy struct {
	Allow      map[string][]string `yaml:"allow,omitempty" json:"allow,omitempty"`           // principal → allowed tags
	Expiration string              `yaml:"expiration,omitempty" json:"expiration,omitempty"` // Override expiration
	Extensions map[string]string   `yaml:"extensions,omitempty" json:"extensions,omitempty"` // Override extensions
}

// Validate checks that the PolicyRulesConfig is valid
func (c *PolicyRulesConfig) Validate() error {
	if c.CAPublicKey == "" {
		return fmt.Errorf("ca_public_key is required")
	}

	if c.OIDC.Issuer == "" {
		return fmt.Errorf("oidc.issuer is required")
	}

	if c.OIDC.Audience == "" {
		return fmt.Errorf("oidc.audience is required")
	}

	if c.Users == nil {
		return fmt.Errorf("users is required")
	}

	// Validate default expiration if provided
	if c.Defaults != nil && c.Defaults.Expiration != "" {
		if err := ValidateDuration(c.Defaults.Expiration); err != nil {
			return fmt.Errorf("invalid defaults.expiration: %w", err)
		}
	}

	// Validate host policy expirations
	for hostname, hostPolicy := range c.Hosts {
		if hostPolicy.Expiration != "" {
			if err := ValidateDuration(hostPolicy.Expiration); err != nil {
				return fmt.Errorf("invalid expiration for host %s: %w", hostname, err)
			}
		}
	}

	return nil
}

// ValidateDuration checks if a duration string is valid
func ValidateDuration(d string) error {
	if _, err := time.ParseDuration(d); err != nil {
		return fmt.Errorf("invalid duration %q: %w", d, err)
	}
	return nil
}

// DefaultExtensions returns the default SSH certificate extensions
func DefaultExtensions() map[string]string {
	return map[string]string{
		"permit-pty":              "",
		"permit-agent-forwarding": "",
		"permit-user-rc":          "",
	}
}

// DefaultExpiration returns the default certificate expiration duration
func DefaultExpiration() string {
	return "5m"
}
