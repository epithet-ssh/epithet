package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver/config"
)

func TestParseCUE(t *testing.T) {
	cue := `
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc: {
	issuer: "https://accounts.google.com"
	audience: "test-client-id"
}

users: {
	"alice@example.com": ["admin"]
	"bob@example.com": ["user"]
}

defaults: {
	allow: {
		root: ["admin"]
		guest: ["user"]
	}
	expiration: "5m"
}
`

	tempFile := filepath.Join(t.TempDir(), "config.cue")
	if err := os.WriteFile(tempFile, []byte(cue), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := config.LoadFromFile(tempFile)
	if err != nil {
		t.Fatalf("failed to parse CUE: %v", err)
	}

	if cfg.OIDC.Issuer != "https://accounts.google.com" {
		t.Errorf("unexpected oidc: %s", cfg.OIDC)
	}

	if len(cfg.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(cfg.Users))
	}

	if tags := cfg.Users["alice@example.com"]; len(tags) != 1 || tags[0] != "admin" {
		t.Errorf("unexpected tags for alice: %v", tags)
	}

	if cfg.Defaults == nil || len(cfg.Defaults.Allow) != 2 {
		t.Errorf("expected 2 principal mappings in defaults.allow")
	}
}

func TestLoadFromFile_CUE(t *testing.T) {
	cfg, err := config.LoadFromFile("../../../tmp/policy.cue")
	if err != nil {
		t.Fatalf("failed to load CUE file: %v", err)
	}

	if cfg.OIDC.Issuer != "https://accounts.google.com" {
		t.Errorf("unexpected oidc: %s", cfg.OIDC)
	}

	if len(cfg.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(cfg.Users))
	}
}

func TestLoadFromFile_YAML(t *testing.T) {
	cfg, err := config.LoadFromFile("../../../tmp/policy.yaml")
	if err != nil {
		t.Fatalf("failed to load YAML file: %v", err)
	}

	if cfg.OIDC.Issuer != "https://accounts.google.com" {
		t.Errorf("unexpected oidc: %s", cfg.OIDC)
	}

	if len(cfg.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(cfg.Users))
	}
}
