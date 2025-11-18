package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"cuelang.org/go/encoding/yaml"
)

// OIDCConfig represents OIDC configuration
type OIDCConfig struct {
	Issuer   string `yaml:"issuer" json:"issuer"`
	Audience string `yaml:"audience" json:"audience"`
}

// PolicyConfig represents the policy server configuration
type PolicyConfig struct {
	CAPublicKey string                 `yaml:"ca_public_key" json:"ca_public_key"`
	OIDC        OIDCConfig             `yaml:"oidc" json:"oidc"`
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

// LoadFromFile loads policy configuration from a file or directory.
//
// For .cue files: Uses CUE's load.Instances to support CUE packages with imports and modules.
// For .yaml/.yml/.json files: Uses direct parsing for standalone data files.
// For directories: Loads all .cue files as a package (supports imports between files).
//
// Examples:
//   - Single YAML: LoadFromFile("policy.yaml")
//   - Single CUE: LoadFromFile("policy.cue")
//   - CUE directory: LoadFromFile("./config")  // loads all .cue files as a package
//   - With imports: CUE files in a directory can import each other
func LoadFromFile(path string) (*PolicyConfig, error) {
	ctx := cuecontext.New()

	// Check if path exists
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	var val cue.Value

	// TODO refactor this to use file globing and load instances. Claude cannot seem to do it.
	// TODO add schema validation

	// Handle directories and .cue files using load.Instances
	if fileInfo.IsDir() || strings.HasSuffix(strings.ToLower(path), ".cue") {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path: %w", err)
		}

		cfg := &load.Config{
			Dir:       filepath.Dir(absPath),
			DataFiles: true,
		}

		var args []string
		if fileInfo.IsDir() {
			args = []string{path}
		} else {
			args = []string{absPath}
		}

		instances := load.Instances(args, cfg)
		if len(instances) == 0 {
			return nil, fmt.Errorf("no instances loaded from %s", path)
		}

		inst := instances[0]
		if inst.Err != nil {
			return nil, fmt.Errorf("failed to load config: %w", inst.Err)
		}

		val = ctx.BuildInstance(inst)
		if err := val.Err(); err != nil {
			return nil, fmt.Errorf("failed to build CUE value: %w", err)
		}
	} else {
		// Handle standalone data files (YAML, JSON)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".yaml", ".yml":
			// Use YAML decoder
			file, err := yaml.Extract("", data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse YAML: %w", err)
			}
			val = ctx.BuildFile(file)
		case ".json":
			// JSON can be compiled directly
			val = ctx.CompileBytes(data)
		default:
			// Try YAML as default
			file, err := yaml.Extract("", data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse file: %w", err)
			}
			val = ctx.BuildFile(file)
		}

		if err := val.Err(); err != nil {
			return nil, fmt.Errorf("failed to build CUE value: %w", err)
		}
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
