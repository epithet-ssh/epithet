package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"cuelang.org/go/cue"
	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

func TestLoadFromFile_PolicyRulesConfig_Minimal(t *testing.T) {
	yaml := `
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc:
  issuer: "https://accounts.google.com"
  audience: "test-client-id"

users:
  "alice@example.com": [alice]
  "bob@example.com": [bob]
`

	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := config.LoadFromFile[policyserver.PolicyRulesConfig](tempFile)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.CAPublicKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..." {
		t.Errorf("unexpected ca_public_key: %s", cfg.CAPublicKey)
	}

	if cfg.OIDC.Issuer != "https://accounts.google.com" {
		t.Errorf("unexpected oidc issuer: %s", cfg.OIDC.Issuer)
	}

	if len(cfg.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(cfg.Users))
	}
}

func TestLoadFromFile_PolicyRulesConfig_WithDefaults(t *testing.T) {
	yaml := `
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc:
  issuer: "https://accounts.google.com"
  audience: "test-client-id"

users:
  "alice@example.com": [admin]

defaults:
  allow:
    root: [admin]
    guest: [visitor]
  expiration: "10m"
  extensions:
    permit-pty: ""
    permit-agent-forwarding: ""
`

	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := config.LoadFromFile[policyserver.PolicyRulesConfig](tempFile)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.Defaults == nil {
		t.Fatal("defaults is nil")
	}

	if len(cfg.Defaults.Allow) != 2 {
		t.Errorf("expected 2 principals in defaults.allow, got %d", len(cfg.Defaults.Allow))
	}

	if cfg.Defaults.Expiration != "10m" {
		t.Errorf("unexpected defaults.expiration: %s", cfg.Defaults.Expiration)
	}
}

func TestLoadFromFile_PolicyRulesConfig_WithHosts(t *testing.T) {
	yaml := `
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc:
  issuer: "https://accounts.google.com"
  audience: "test-client-id"

users:
  "alice@example.com": [dba-tag]

hosts:
  prod-db-01:
    allow:
      postgres: [dba-tag]
    expiration: "2m"
`

	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := config.LoadFromFile[policyserver.PolicyRulesConfig](tempFile)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if len(cfg.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(cfg.Hosts))
	}

	hostPolicy := cfg.Hosts["prod-db-01"]
	if hostPolicy == nil {
		t.Fatal("host policy is nil")
	}

	if hostPolicy.Expiration != "2m" {
		t.Errorf("unexpected expiration: %s", hostPolicy.Expiration)
	}
}

// testCLIConfig is a local test struct that mirrors the CLI config structure.
// This is used for testing the generic loader without importing cmd/epithet.
type testCLIConfig struct {
	Insecure  bool              `yaml:"insecure" json:"insecure"`
	Verbose   int               `yaml:"verbose" json:"verbose"`
	LogFile   string            `yaml:"log_file" json:"log_file"`
	TLSCACert string            `yaml:"tls_ca_cert" json:"tls_ca_cert"`
	Agent     *testAgentConfig  `yaml:"agent,omitempty" json:"agent,omitempty"`
	CA        *testCAConfig     `yaml:"ca,omitempty" json:"ca,omitempty"`
	Auth      *testAuthConfig   `yaml:"auth,omitempty" json:"auth,omitempty"`
	Policy    *testPolicyConfig `yaml:"policy,omitempty" json:"policy,omitempty"`
}

type testAgentConfig struct {
	Match []string `yaml:"match" json:"match"`
	CaURL string   `yaml:"ca_url" json:"ca_url"`
	Auth  string   `yaml:"auth" json:"auth"`
}

type testCAConfig struct {
	Policy string `yaml:"policy" json:"policy"`
	Listen string `yaml:"listen" json:"listen"`
}

type testAuthConfig struct {
	OIDC *testOIDCConfig `yaml:"oidc,omitempty" json:"oidc,omitempty"`
}

type testOIDCConfig struct {
	Issuer       string   `yaml:"issuer" json:"issuer"`
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"client_secret"`
	Scopes       []string `yaml:"scopes" json:"scopes"`
}

type testPolicyConfig struct {
	ConfigFile string `yaml:"config_file" json:"config_file"`
	Listen     string `yaml:"listen" json:"listen"`
	CAPubkey   string `yaml:"ca_pubkey" json:"ca_pubkey"`
}

func TestLoadFromFile_CLIConfig(t *testing.T) {
	yaml := `
insecure: true
verbose: 2
log_file: "/var/log/epithet.log"

agent:
  match:
    - "*.example.com"
    - "*.internal"
  ca_url: "https://ca.example.com"
  auth: "epithet auth oidc --issuer https://accounts.google.com"

ca:
  policy: "https://policy.example.com"
  listen: "0.0.0.0:8443"

auth:
  oidc:
    issuer: "https://accounts.google.com"
    client_id: "my-client-id"
    scopes:
      - openid
      - email
`

	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := config.LoadFromFile[testCLIConfig](tempFile)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if !cfg.Insecure {
		t.Error("expected insecure to be true")
	}

	if cfg.Verbose != 2 {
		t.Errorf("expected verbose 2, got %d", cfg.Verbose)
	}

	if cfg.LogFile != "/var/log/epithet.log" {
		t.Errorf("unexpected log_file: %s", cfg.LogFile)
	}

	if cfg.Agent == nil {
		t.Fatal("agent is nil")
	}

	if len(cfg.Agent.Match) != 2 {
		t.Errorf("expected 2 match patterns, got %d", len(cfg.Agent.Match))
	}

	if cfg.Agent.CaURL != "https://ca.example.com" {
		t.Errorf("unexpected ca_url: %s", cfg.Agent.CaURL)
	}

	if cfg.CA == nil {
		t.Fatal("ca is nil")
	}

	if cfg.CA.Listen != "0.0.0.0:8443" {
		t.Errorf("unexpected ca listen: %s", cfg.CA.Listen)
	}

	if cfg.Auth == nil || cfg.Auth.OIDC == nil {
		t.Fatal("auth.oidc is nil")
	}

	if cfg.Auth.OIDC.ClientID != "my-client-id" {
		t.Errorf("unexpected client_id: %s", cfg.Auth.OIDC.ClientID)
	}

	if len(cfg.Auth.OIDC.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(cfg.Auth.OIDC.Scopes))
	}
}

func TestLoadFromFile_JSON(t *testing.T) {
	json := `{
  "insecure": true,
  "agent": {
    "match": ["*.example.com"],
    "ca_url": "https://ca.example.com"
  }
}`

	tempFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tempFile, []byte(json), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := config.LoadFromFile[testCLIConfig](tempFile)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if !cfg.Insecure {
		t.Error("expected insecure to be true")
	}

	if cfg.Agent == nil {
		t.Fatal("agent is nil")
	}

	if len(cfg.Agent.Match) != 1 {
		t.Errorf("expected 1 match pattern, got %d", len(cfg.Agent.Match))
	}
}

func TestLoadFromFile_NonexistentFile(t *testing.T) {
	_, err := config.LoadFromFile[testCLIConfig]("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadValue_DirectPathLookup(t *testing.T) {
	yaml := `
insecure: true
verbose: 2

agent:
  match:
    - "*.example.com"
    - "*.internal"
  ca_url: "https://ca.example.com"
`

	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	val, err := config.LoadValue(tempFile)
	if err != nil {
		t.Fatalf("failed to load value: %v", err)
	}

	// Test direct path lookups (this is how the kong resolver uses it)
	tests := []struct {
		path     string
		wantStr  string
		wantBool bool
		wantInt  int64
		isBool   bool
		isInt    bool
	}{
		{"insecure", "", true, 0, true, false},
		{"verbose", "", false, 2, false, true},
		{"agent.ca_url", "https://ca.example.com", false, 0, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			v := val.LookupPath(cue.ParsePath(tt.path))
			if !v.Exists() {
				t.Errorf("path %s does not exist", tt.path)
				return
			}

			if tt.isBool {
				b, err := v.Bool()
				if err != nil {
					t.Errorf("failed to get bool: %v", err)
				} else if b != tt.wantBool {
					t.Errorf("got %v, want %v", b, tt.wantBool)
				}
			} else if tt.isInt {
				i, err := v.Int64()
				if err != nil {
					t.Errorf("failed to get int: %v", err)
				} else if i != tt.wantInt {
					t.Errorf("got %d, want %d", i, tt.wantInt)
				}
			} else {
				s, err := v.String()
				if err != nil {
					t.Errorf("failed to get string: %v", err)
				} else if s != tt.wantStr {
					t.Errorf("got %q, want %q", s, tt.wantStr)
				}
			}
		})
	}

	// Test list lookup
	matchVal := val.LookupPath(cue.ParsePath("agent.match"))
	if !matchVal.Exists() {
		t.Fatal("agent.match does not exist")
	}

	iter, err := matchVal.List()
	if err != nil {
		t.Fatalf("failed to get list: %v", err)
	}

	var matches []string
	for iter.Next() {
		s, _ := iter.Value().String()
		matches = append(matches, s)
	}

	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
	if matches[0] != "*.example.com" {
		t.Errorf("first match: got %q, want %q", matches[0], "*.example.com")
	}
}

func TestPolicyRulesConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     policyserver.PolicyRulesConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", Audience: "aud"},
				Users:       map[string][]string{"alice": {"tag"}},
			},
			wantErr: false,
		},
		{
			name: "missing ca_public_key",
			cfg: policyserver.PolicyRulesConfig{
				OIDC:  policyserver.OIDCConfig{Issuer: "https://issuer", Audience: "aud"},
				Users: map[string][]string{"alice": {"tag"}},
			},
			wantErr: true,
		},
		{
			name: "missing oidc issuer",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Audience: "aud"},
				Users:       map[string][]string{"alice": {"tag"}},
			},
			wantErr: true,
		},
		{
			name: "missing oidc audience",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer"},
				Users:       map[string][]string{"alice": {"tag"}},
			},
			wantErr: true,
		},
		{
			name: "missing users",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", Audience: "aud"},
			},
			wantErr: true,
		},
		{
			name: "invalid default expiration",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", Audience: "aud"},
				Users:       map[string][]string{"alice": {"tag"}},
				Defaults:    &policyserver.DefaultPolicy{Expiration: "invalid"},
			},
			wantErr: true,
		},
		{
			name: "valid default expiration",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", Audience: "aud"},
				Users:       map[string][]string{"alice": {"tag"}},
				Defaults:    &policyserver.DefaultPolicy{Expiration: "5m"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultExtensions(t *testing.T) {
	ext := policyserver.DefaultExtensions()

	if len(ext) != 3 {
		t.Errorf("expected 3 default extensions, got %d", len(ext))
	}

	if _, ok := ext["permit-pty"]; !ok {
		t.Error("expected permit-pty extension")
	}
}

func TestDefaultExpiration(t *testing.T) {
	exp := policyserver.DefaultExpiration()

	if exp != "5m" {
		t.Errorf("expected default expiration '5m', got %s", exp)
	}
}

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name    string
		d       string
		wantErr bool
	}{
		{"valid minutes", "5m", false},
		{"valid hours", "2h", false},
		{"valid seconds", "30s", false},
		{"valid complex", "1h30m", false},
		{"invalid", "invalid", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policyserver.ValidateDuration(tt.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDuration(%q) error = %v, wantErr %v", tt.d, err, tt.wantErr)
			}
		})
	}
}

// Tests for LoadAndUnifyPaths

func TestLoadAndUnifyPaths_SingleYAML(t *testing.T) {
	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(yamlFile, []byte(`
agent:
  ca_url: "https://ca.example.com"
`), 0644); err != nil {
		t.Fatal(err)
	}

	val, err := config.LoadAndUnifyPaths([]string{yamlFile})
	if err != nil {
		t.Fatalf("LoadAndUnifyPaths failed: %v", err)
	}

	caURL, err := val.LookupPath(cue.ParsePath("agent.ca_url")).String()
	if err != nil {
		t.Fatalf("failed to get agent.ca_url: %v", err)
	}
	if caURL != "https://ca.example.com" {
		t.Errorf("expected https://ca.example.com, got %s", caURL)
	}
}

func TestLoadAndUnifyPaths_SingleCUE(t *testing.T) {
	dir := t.TempDir()
	cueFile := filepath.Join(dir, "config.cue")
	if err := os.WriteFile(cueFile, []byte(`
agent: {
	ca_url: "https://ca.example.com"
	port: 8080
}
`), 0644); err != nil {
		t.Fatal(err)
	}

	val, err := config.LoadAndUnifyPaths([]string{cueFile})
	if err != nil {
		t.Fatalf("LoadAndUnifyPaths failed: %v", err)
	}

	caURL, err := val.LookupPath(cue.ParsePath("agent.ca_url")).String()
	if err != nil {
		t.Fatalf("failed to get agent.ca_url: %v", err)
	}
	if caURL != "https://ca.example.com" {
		t.Errorf("expected https://ca.example.com, got %s", caURL)
	}

	port, err := val.LookupPath(cue.ParsePath("agent.port")).Int64()
	if err != nil {
		t.Fatalf("failed to get agent.port: %v", err)
	}
	if port != 8080 {
		t.Errorf("expected 8080, got %d", port)
	}
}

func TestLoadAndUnifyPaths_MultipleFilesCompatible(t *testing.T) {
	dir := t.TempDir()

	// First file with ca_url
	file1 := filepath.Join(dir, "base.yaml")
	if err := os.WriteFile(file1, []byte(`
agent:
  ca_url: "https://ca.example.com"
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Second file with match patterns (different field, compatible)
	file2 := filepath.Join(dir, "matches.yaml")
	if err := os.WriteFile(file2, []byte(`
agent:
  match:
    - "*.example.com"
`), 0644); err != nil {
		t.Fatal(err)
	}

	val, err := config.LoadAndUnifyPaths([]string{file1, file2})
	if err != nil {
		t.Fatalf("LoadAndUnifyPaths failed: %v", err)
	}

	// Check ca_url from first file
	caURL, err := val.LookupPath(cue.ParsePath("agent.ca_url")).String()
	if err != nil {
		t.Fatalf("failed to get agent.ca_url: %v", err)
	}
	if caURL != "https://ca.example.com" {
		t.Errorf("expected https://ca.example.com, got %s", caURL)
	}

	// Check match from second file
	matchVal := val.LookupPath(cue.ParsePath("agent.match"))
	iter, err := matchVal.List()
	if err != nil {
		t.Fatalf("failed to get agent.match as list: %v", err)
	}

	var matches []string
	for iter.Next() {
		s, _ := iter.Value().String()
		matches = append(matches, s)
	}
	if len(matches) != 1 || matches[0] != "*.example.com" {
		t.Errorf("expected [*.example.com], got %v", matches)
	}
}

func TestLoadAndUnifyPaths_ConflictingValues(t *testing.T) {
	dir := t.TempDir()

	// First file with ca_url
	file1 := filepath.Join(dir, "base.yaml")
	if err := os.WriteFile(file1, []byte(`
agent:
  ca_url: "https://ca1.example.com"
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Second file with different ca_url (conflict!)
	file2 := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(file2, []byte(`
agent:
  ca_url: "https://ca2.example.com"
`), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := config.LoadAndUnifyPaths([]string{file1, file2})
	if err == nil {
		t.Fatal("expected error for conflicting values, got nil")
	}
}

func TestLoadAndUnifyPaths_GlobPattern(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "config.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create multiple yaml files
	if err := os.WriteFile(filepath.Join(confDir, "a.yaml"), []byte(`
settings:
  a: true
`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(confDir, "b.yaml"), []byte(`
settings:
  b: true
`), 0644); err != nil {
		t.Fatal(err)
	}

	val, err := config.LoadAndUnifyPaths([]string{filepath.Join(confDir, "*.yaml")})
	if err != nil {
		t.Fatalf("LoadAndUnifyPaths failed: %v", err)
	}

	// Check both values are present
	a, err := val.LookupPath(cue.ParsePath("settings.a")).Bool()
	if err != nil {
		t.Fatalf("failed to get settings.a: %v", err)
	}
	if !a {
		t.Error("expected settings.a to be true")
	}

	b, err := val.LookupPath(cue.ParsePath("settings.b")).Bool()
	if err != nil {
		t.Fatalf("failed to get settings.b: %v", err)
	}
	if !b {
		t.Error("expected settings.b to be true")
	}
}

func TestLoadAndUnifyPaths_MissingFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "exists.yaml")
	if err := os.WriteFile(yamlFile, []byte(`
key: value
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Include a non-existent file in the patterns
	val, err := config.LoadAndUnifyPaths([]string{
		filepath.Join(dir, "does-not-exist.yaml"),
		yamlFile,
	})
	if err != nil {
		t.Fatalf("LoadAndUnifyPaths failed: %v", err)
	}

	// The existing file's value should be present
	key, err := val.LookupPath(cue.ParsePath("key")).String()
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}
	if key != "value" {
		t.Errorf("expected 'value', got %s", key)
	}
}

func TestLoadAndUnifyPaths_EmptyResult(t *testing.T) {
	dir := t.TempDir()

	// No files exist
	val, err := config.LoadAndUnifyPaths([]string{
		filepath.Join(dir, "does-not-exist.yaml"),
	})
	if err != nil {
		t.Fatalf("LoadAndUnifyPaths failed: %v", err)
	}

	// Should return an empty object, not an error
	if !val.Exists() {
		t.Error("expected value to exist (empty object)")
	}
}

func TestLoadAndUnifyPaths_MixedFileTypes(t *testing.T) {
	dir := t.TempDir()

	// YAML file
	yamlFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(yamlFile, []byte(`
from_yaml: true
`), 0644); err != nil {
		t.Fatal(err)
	}

	// CUE file
	cueFile := filepath.Join(dir, "config.cue")
	if err := os.WriteFile(cueFile, []byte(`
from_cue: true
`), 0644); err != nil {
		t.Fatal(err)
	}

	// JSON file
	jsonFile := filepath.Join(dir, "config.json")
	if err := os.WriteFile(jsonFile, []byte(`{"from_json": true}`), 0644); err != nil {
		t.Fatal(err)
	}

	val, err := config.LoadAndUnifyPaths([]string{yamlFile, cueFile, jsonFile})
	if err != nil {
		t.Fatalf("LoadAndUnifyPaths failed: %v", err)
	}

	// Check all values are present
	fromYAML, _ := val.LookupPath(cue.ParsePath("from_yaml")).Bool()
	if !fromYAML {
		t.Error("expected from_yaml to be true")
	}

	fromCUE, _ := val.LookupPath(cue.ParsePath("from_cue")).Bool()
	if !fromCUE {
		t.Error("expected from_cue to be true")
	}

	fromJSON, _ := val.LookupPath(cue.ParsePath("from_json")).Bool()
	if !fromJSON {
		t.Error("expected from_json to be true")
	}
}
