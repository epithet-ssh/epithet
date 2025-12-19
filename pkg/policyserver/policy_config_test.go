package policyserver_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

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

func TestDiscoveryHash_Deterministic(t *testing.T) {
	cfg := policyserver.PolicyRulesConfig{
		Hosts: map[string]*policyserver.HostPolicy{
			"host1.example.com": {},
			"host2.example.com": {},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"wheel":      {"admin"},
				"developers": {"eng"},
			},
		},
	}

	hash1 := cfg.DiscoveryHash()
	hash2 := cfg.DiscoveryHash()

	if hash1 != hash2 {
		t.Errorf("DiscoveryHash() not deterministic: %q != %q", hash1, hash2)
	}

	if len(hash1) != 12 {
		t.Errorf("expected 12 character hash, got %d characters: %q", len(hash1), hash1)
	}
}

func TestDiscoveryHash_OrderIndependent(t *testing.T) {
	// Two configs with same hosts in different order should produce same hash
	cfg1 := policyserver.PolicyRulesConfig{
		Hosts: map[string]*policyserver.HostPolicy{
			"host1.example.com": {},
			"host2.example.com": {},
			"host3.example.com": {},
		},
	}

	cfg2 := policyserver.PolicyRulesConfig{
		Hosts: map[string]*policyserver.HostPolicy{
			"host3.example.com": {},
			"host1.example.com": {},
			"host2.example.com": {},
		},
	}

	hash1 := cfg1.DiscoveryHash()
	hash2 := cfg2.DiscoveryHash()

	if hash1 != hash2 {
		t.Errorf("DiscoveryHash() should be order-independent: %q != %q", hash1, hash2)
	}
}

func TestDiscoveryHash_ChangesWithHosts(t *testing.T) {
	cfg1 := policyserver.PolicyRulesConfig{
		Hosts: map[string]*policyserver.HostPolicy{
			"host1.example.com": {},
		},
	}

	cfg2 := policyserver.PolicyRulesConfig{
		Hosts: map[string]*policyserver.HostPolicy{
			"host1.example.com": {},
			"host2.example.com": {},
		},
	}

	hash1 := cfg1.DiscoveryHash()
	hash2 := cfg2.DiscoveryHash()

	if hash1 == hash2 {
		t.Errorf("DiscoveryHash() should change when hosts change: %q == %q", hash1, hash2)
	}
}

func TestDiscoveryHash_ChangesWithDefaults(t *testing.T) {
	cfg1 := policyserver.PolicyRulesConfig{
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"wheel": {"admin"},
			},
		},
	}

	cfg2 := policyserver.PolicyRulesConfig{
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"wheel":      {"admin"},
				"developers": {"eng"},
			},
		},
	}

	hash1 := cfg1.DiscoveryHash()
	hash2 := cfg2.DiscoveryHash()

	if hash1 == hash2 {
		t.Errorf("DiscoveryHash() should change when defaults.allow changes: %q == %q", hash1, hash2)
	}
}

func TestDiscoveryHash_EmptyConfig(t *testing.T) {
	cfg := policyserver.PolicyRulesConfig{}

	hash := cfg.DiscoveryHash()

	if len(hash) != 12 {
		t.Errorf("expected 12 character hash even for empty config, got %d characters: %q", len(hash), hash)
	}
}
