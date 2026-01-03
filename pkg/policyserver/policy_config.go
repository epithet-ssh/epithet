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
type PolicyRulesConfig struct {
	CAPublicKey string                 `yaml:"ca_pubkey" json:"ca_pubkey"`
	OIDC        OIDCConfig             `yaml:"oidc" json:"oidc"`
	Users       map[string][]string    `yaml:"users" json:"users"` // user identity → tags
	Defaults    *DefaultPolicy         `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Hosts       map[string]*HostPolicy `yaml:"hosts,omitempty" json:"hosts,omitempty"` // hostname → host policy
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

// Bootstrap represents the bootstrap endpoint response
type Bootstrap struct {
	Auth BootstrapAuth `json:"auth"`
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

// DiscoveryHash computes a content-addressable hash of the policy rules.
// This hash changes when the matching policy changes (hosts, users, etc.).
// Returns a 12-character hex string.
func (c *PolicyRulesConfig) DiscoveryHash() string {
	// Create a deterministic representation of match-relevant config
	// Currently: Hosts map (keys define what hosts are handled)
	//            Defaults.Allow (defines default match behavior)
	// Future: could include user patterns, port patterns, etc.

	h := sha256.New()
	enc := json.NewEncoder(h)

	// Hash hosts map keys (sorted for determinism)
	hostKeys := make([]string, 0, len(c.Hosts))
	for k := range c.Hosts {
		hostKeys = append(hostKeys, k)
	}
	sort.Strings(hostKeys)
	enc.Encode(hostKeys)

	// Hash defaults.Allow if present (sorted keys)
	if c.Defaults != nil && len(c.Defaults.Allow) > 0 {
		allowKeys := make([]string, 0, len(c.Defaults.Allow))
		for k := range c.Defaults.Allow {
			allowKeys = append(allowKeys, k)
		}
		sort.Strings(allowKeys)
		enc.Encode(allowKeys)
	}

	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:12]
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

// BootstrapHash computes a content-addressable hash of the auth configuration.
// This hash changes when the auth config changes (issuer, client_id, scopes).
// Returns a 12-character hex string.
func (c *PolicyRulesConfig) BootstrapHash() string {
	h := sha256.New()
	enc := json.NewEncoder(h)

	// Hash the bootstrap auth config (deterministic JSON)
	auth := c.BootstrapAuth()
	enc.Encode(auth)

	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:12]
}
