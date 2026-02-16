package policyserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// PolicyRulesConfig represents the policy server rules configuration.
// This defines users, hosts, and access policies - not CLI flags.
// For new deployments, consider using ServerConfig + PolicyConfig separately
// to enable dynamic policy loading via policy_url.
type PolicyRulesConfig struct {
	CAPublicKey string                 `yaml:"ca_pubkey" json:"ca_pubkey"`
	OIDC        OIDCConfig             `yaml:"oidc" json:"oidc"`
	Users       map[string][]string    `yaml:"users" json:"users"` // user identity → tags
	Defaults    *DefaultPolicy         `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Hosts       map[string]*HostPolicy `yaml:"hosts,omitempty" json:"hosts,omitempty"` // hostname → host policy
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
// Currently only supports OIDC auth type.
func (c *ServerConfig) BootstrapAuth() BootstrapAuth {
	scopes := c.OIDC.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}

	return BootstrapAuth{
		Type:         "oidc",
		Issuer:       c.OIDC.Issuer,
		ClientID:     c.OIDC.ClientID,
		ClientSecret: c.OIDC.ClientSecret,
		Scopes:       scopes,
	}
}

// ComputeUnauthDiscoveryHash computes a content-addressable hash of the auth configuration.
// This is the hash used for unauthenticated discovery (the bootstrap replacement).
// Returns a 12-character hex string.
func ComputeUnauthDiscoveryHash(auth BootstrapAuth) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	enc.Encode(auth)

	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:12]
}

// ComputeAuthDiscoveryHash computes a content-addressable hash of auth config + match patterns.
// This is the hash used for authenticated discovery (returns auth + match patterns).
// Returns a 12-character hex string.
func ComputeAuthDiscoveryHash(auth BootstrapAuth, matchPatterns []string) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	enc.Encode(auth)

	// Sort patterns for determinism.
	sorted := make([]string, len(matchPatterns))
	copy(sorted, matchPatterns)
	sort.Strings(sorted)
	enc.Encode(sorted)

	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:12]
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
	Issuer       string   `yaml:"issuer" json:"issuer"`
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret,omitempty" json:"client_secret,omitempty"` // Optional, for confidential clients
	Scopes       []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`               // Optional, defaults to ["openid", "profile", "email"]
}

// DefaultScopes returns the default OIDC scopes
func DefaultScopes() []string {
	return []string{"openid", "profile", "email"}
}

// BootstrapAuth represents the auth configuration returned by the bootstrap endpoint.
// The Type field discriminates between auth methods.
type BootstrapAuth struct {
	// Type identifies the auth method: "oidc" or "command"
	Type string `json:"type"`

	// OIDC fields (when type="oidc")
	Issuer       string   `json:"issuer,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`

	// Command field (when type="command") - opaque string
	Command string `json:"command,omitempty"`
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

// BootstrapAuth returns the auth configuration for the bootstrap endpoint.
// Currently only supports OIDC auth type.
func (c *PolicyRulesConfig) BootstrapAuth() BootstrapAuth {
	scopes := c.OIDC.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}

	return BootstrapAuth{
		Type:         "oidc",
		Issuer:       c.OIDC.Issuer,
		ClientID:     c.OIDC.ClientID,
		ClientSecret: c.OIDC.ClientSecret,
		Scopes:       scopes,
	}
}
