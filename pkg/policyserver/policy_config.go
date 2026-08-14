package policyserver

import (
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/wire"
)

// PolicyRulesConfig represents the policy server rules configuration.
// This defines users, hosts, and access policies - not CLI flags.
// For new deployments, consider using ServerConfig + PolicyConfig separately
// to enable dynamic policy loading via policy_url.
type PolicyRulesConfig struct {
	CAPublicKey string              `yaml:"ca_pubkey" json:"ca_pubkey"`
	OIDC        OIDCConfig          `yaml:"oidc" json:"oidc"`
	Users       map[string][]string `yaml:"users" json:"users"` // user identity → tags
	Defaults    *Rules              `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Hosts       map[string]*Rules   `yaml:"hosts,omitempty" json:"hosts,omitempty"` // hostname → host rules
}

// ServerConfig contains static server configuration loaded at startup.
// These settings cannot be changed without restarting the server.
type ServerConfig struct {
	CAPublicKey string     `yaml:"ca_pubkey" json:"ca_pubkey"`
	OIDC        OIDCConfig `yaml:"oidc" json:"oidc"`
	PolicyURL   string     `yaml:"policy_url,omitempty" json:"policy_url,omitempty"` // URL to load dynamic policy from
}

// Validate checks that the ServerConfig is valid.
func (c *ServerConfig) Validate() error {
	if c.CAPublicKey == "" {
		return fmt.Errorf("ca_pubkey is required")
	}

	if c.OIDC.Issuer == "" {
		return fmt.Errorf("oidc.issuer is required")
	}

	if c.OIDC.ClientID == "" {
		return fmt.Errorf("oidc.client_id is required")
	}

	return nil
}

// BootstrapAuth returns the auth configuration for the bootstrap endpoint.
func (c *ServerConfig) BootstrapAuth() wire.AuthConfig {
	return wire.AuthConfig{
		Issuer:       c.OIDC.Issuer,
		ClientID:     c.OIDC.ClientID,
		ClientSecret: c.OIDC.ClientSecret,
	}
}

// ExtractPolicyConfig extracts the dynamic policy portion from PolicyRulesConfig.
// Used for backwards compatibility when policy is defined inline.
func (c *PolicyRulesConfig) ExtractPolicyConfig() *PolicyConfig {
	return &PolicyConfig{
		Users:    c.Users,
		Defaults: c.Defaults,
		Hosts:    c.Hosts,
	}
}

// ExtractServerConfig extracts the static server portion from PolicyRulesConfig.
// Used for backwards compatibility when all config is in one file.
func (c *PolicyRulesConfig) ExtractServerConfig() *ServerConfig {
	return &ServerConfig{
		CAPublicKey: c.CAPublicKey,
		OIDC:        c.OIDC,
	}
}

// OIDCConfig represents OIDC configuration for token validation
type OIDCConfig struct {
	Issuer       string `yaml:"issuer" json:"issuer"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret,omitempty" json:"client_secret,omitempty"` // Optional, for confidential clients
}

// Rules defines a set of policy rules: which principals are allowed, cert
// expiration, and cert extensions. It is used both as the global default
// (PolicyConfig.Defaults) and as a per-host override (PolicyConfig.Hosts),
// since the two were structurally identical and only differed by name.
type Rules struct {
	Allow      map[string][]string `yaml:"allow,omitempty" json:"allow,omitempty"`           // principal → allowed tags
	Expiration string              `yaml:"expiration,omitempty" json:"expiration,omitempty"` // Cert expiration (e.g., "5m")
	Extensions map[string]string   `yaml:"extensions,omitempty" json:"extensions,omitempty"` // Cert extensions
}

// Validate checks that the PolicyRulesConfig is valid
func (c *PolicyRulesConfig) Validate() error {
	if c.CAPublicKey == "" {
		return fmt.Errorf("ca_public_key is required")
	}

	if c.OIDC.Issuer == "" {
		return fmt.Errorf("oidc.issuer is required")
	}

	if c.OIDC.ClientID == "" {
		return fmt.Errorf("oidc.client_id is required")
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

	// Validate host rule expirations
	for hostname, hostRules := range c.Hosts {
		if hostRules.Expiration != "" {
			if err := ValidateDuration(hostRules.Expiration); err != nil {
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
