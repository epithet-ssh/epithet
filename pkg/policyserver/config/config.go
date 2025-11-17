package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/encoding/yaml"
)

// PolicyConfig represents the policy server configuration
type PolicyConfig struct {
	CAPublicKey string                 `yaml:"ca_public_key" json:"ca_public_key"`
	OIDC        string                 `yaml:"oidc" json:"oidc"`   // OIDC issuer URL
	Users       map[string][]string    `yaml:"users" json:"users"` // user identity → tags
	Defaults    *DefaultPolicy         `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Hosts       map[string]*HostPolicy `yaml:"hosts,omitempty" json:"hosts,omitempty"` // hostname → host policy
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

// LoadFromFile loads policy configuration from a file
// Detects format based on file extension: .yaml/.yml for YAML, .cue for CUE
func LoadFromFile(path string) (*PolicyConfig, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Determine format from extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".cue":
		return ParseCUE(data)
	case ".yaml", ".yml":
		return ParseYAML(data)
	default:
		// Default to YAML for backwards compatibility
		return ParseYAML(data)
	}
}

// Parse parses policy configuration from bytes (YAML format)
// Deprecated: Use ParseYAML or ParseCUE explicitly
func Parse(data []byte) (*PolicyConfig, error) {
	return ParseYAML(data)
}

// ParseYAML parses policy configuration from YAML bytes
func ParseYAML(data []byte) (*PolicyConfig, error) {
	ctx := cuecontext.New()

	// Decode YAML into CUE value
	// This handles casual YAML syntax (unquoted strings, etc)
	file, err := yaml.Extract("", data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Build CUE value from the AST
	val := ctx.BuildFile(file)
	if err := val.Err(); err != nil {
		return nil, fmt.Errorf("failed to build CUE value: %w", err)
	}

	// Decode into Go struct
	var config PolicyConfig
	if err := val.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

// ParseCUE parses policy configuration from CUE bytes
func ParseCUE(data []byte) (*PolicyConfig, error) {
	ctx := cuecontext.New()

	// Compile CUE source directly
	val := ctx.CompileBytes(data)
	if err := val.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse CUE: %w", err)
	}

	// Decode into Go struct
	var config PolicyConfig
	if err := val.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

// Validate checks that the configuration is valid
func (c *PolicyConfig) Validate() error {
	if c.CAPublicKey == "" {
		return fmt.Errorf("ca_public_key is required")
	}

	if c.OIDC == "" {
		return fmt.Errorf("oidc is required")
	}

	if c.Users == nil {
		return fmt.Errorf("users is required")
	}

	// Validate default expiration if provided
	if c.Defaults != nil && c.Defaults.Expiration != "" {
		if err := validateDuration(c.Defaults.Expiration); err != nil {
			return fmt.Errorf("invalid defaults.expiration: %w", err)
		}
	}

	// Validate host policy expirations
	for hostname, hostPolicy := range c.Hosts {
		if hostPolicy.Expiration != "" {
			if err := validateDuration(hostPolicy.Expiration); err != nil {
				return fmt.Errorf("invalid expiration for host %s: %w", hostname, err)
			}
		}
	}

	return nil
}

// validateDuration checks if a duration string is valid
func validateDuration(d string) error {
	// Try to parse as Go duration
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
