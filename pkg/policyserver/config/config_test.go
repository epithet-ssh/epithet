package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver/config"
)

func TestParse_MinimalConfig(t *testing.T) {
	yaml := `
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc:
  issuer: "https://accounts.google.com"
  audience: "test-client-id"

users:
  "alice@example.com": [alice]
  "bob@example.com": [bob]
`

	// Write to temp file
	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := config.LoadFromFile(tempFile)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.CAPublicKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..." {
		t.Errorf("unexpected ca_public_key: %s", cfg.CAPublicKey)
	}

	if cfg.OIDC.Issuer != "https://accounts.google.com" {
		t.Errorf("unexpected oidc: %s", cfg.OIDC)
	}

	if len(cfg.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(cfg.Users))
	}

	if principals := cfg.Users["alice@example.com"]; len(principals) != 1 || principals[0] != "alice" {
		t.Errorf("unexpected principals for alice: %v", principals)
	}
}

func TestParse_WithDefaults(t *testing.T) {
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

	cfg, err := config.LoadFromFile(tempFile)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.Defaults == nil {
		t.Fatal("defaults is nil")
	}

	if len(cfg.Defaults.Allow) != 2 {
		t.Errorf("expected 2 principals in defaults.allow, got %d", len(cfg.Defaults.Allow))
	}

	if tags := cfg.Defaults.Allow["root"]; len(tags) != 1 || tags[0] != "admin" {
		t.Errorf("unexpected tags for root: %v", tags)
	}

	if cfg.Defaults.Expiration != "10m" {
		t.Errorf("unexpected defaults.expiration: %s", cfg.Defaults.Expiration)
	}

	if len(cfg.Defaults.Extensions) != 2 {
		t.Errorf("expected 2 extensions, got %d", len(cfg.Defaults.Extensions))
	}
}

func TestParse_WithHosts(t *testing.T) {
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

	cfg, err := config.LoadFromFile(tempFile)
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

	if tags := hostPolicy.Allow["postgres"]; len(tags) != 1 || tags[0] != "dba-tag" {
		t.Errorf("unexpected tags for postgres principal on prod-db-01: %v", tags)
	}

	if hostPolicy.Expiration != "2m" {
		t.Errorf("unexpected expiration: %s", hostPolicy.Expiration)
	}
}

func TestParse_MissingCAPublicKey(t *testing.T) {
	yaml := `
oidc:
  issuer: "https://accounts.google.com"
  audience: "test-client-id"
users:
  "alice@example.com": [alice]
`

	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := config.LoadFromFile(tempFile)
	if err == nil {
		t.Fatal("expected error for missing ca_public_key, got nil")
	}
}

func TestParse_MissingOIDC(t *testing.T) {
	yaml := `
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
users:
  "alice@example.com": [alice]
`

	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := config.LoadFromFile(tempFile)
	if err == nil {
		t.Fatal("expected error for missing oidc, got nil")
	}
}

func TestParse_InvalidExpiration(t *testing.T) {
	yaml := `
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc:
  issuer: "https://accounts.google.com"
  audience: "test-client-id"
users:
  "alice@example.com": [alice]
defaults:
  expiration: "invalid-duration"
`

	tempFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tempFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := config.LoadFromFile(tempFile)
	if err == nil {
		t.Fatal("expected error for invalid expiration, got nil")
	}
}

func TestLoadFromFile(t *testing.T) {
	// Test with the example file from tmp/policy.yaml
	cfg, err := config.LoadFromFile("../../../tmp/policy.yaml")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.OIDC.Issuer != "https://accounts.google.com" {
		t.Errorf("unexpected oidc: %s", cfg.OIDC)
	}

	if len(cfg.Users) == 0 {
		t.Error("expected users to be populated")
	}
}

func TestDefaultExtensions(t *testing.T) {
	ext := config.DefaultExtensions()

	if len(ext) != 3 {
		t.Errorf("expected 3 default extensions, got %d", len(ext))
	}

	if _, ok := ext["permit-pty"]; !ok {
		t.Error("expected permit-pty extension")
	}
}

func TestDefaultExpiration(t *testing.T) {
	exp := config.DefaultExpiration()

	if exp != "5m" {
		t.Errorf("expected default expiration '5m', got %s", exp)
	}
}
