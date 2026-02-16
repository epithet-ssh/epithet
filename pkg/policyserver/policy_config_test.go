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
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
				Users:       map[string][]string{"alice": {"tag"}},
			},
			wantErr: false,
		},
		{
			name: "missing ca_public_key",
			cfg: policyserver.PolicyRulesConfig{
				OIDC:  policyserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
				Users: map[string][]string{"alice": {"tag"}},
			},
			wantErr: true,
		},
		{
			name: "missing oidc issuer",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{ClientID: "client-id"},
				Users:       map[string][]string{"alice": {"tag"}},
			},
			wantErr: true,
		},
		{
			name: "missing oidc client_id",
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
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
			},
			wantErr: true,
		},
		{
			name: "invalid default expiration",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
				Users:       map[string][]string{"alice": {"tag"}},
				Defaults:    &policyserver.DefaultPolicy{Expiration: "invalid"},
			},
			wantErr: true,
		},
		{
			name: "valid default expiration",
			cfg: policyserver.PolicyRulesConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
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

func TestComputeAuthDiscoveryHash_Deterministic(t *testing.T) {
	auth := policyserver.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "test-client-id",
		Scopes:   []string{"openid", "profile", "email"},
	}
	patterns := []string{"host1.example.com", "host2.example.com"}

	hash1 := policyserver.ComputeAuthDiscoveryHash(auth, patterns)
	hash2 := policyserver.ComputeAuthDiscoveryHash(auth, patterns)

	if hash1 != hash2 {
		t.Errorf("ComputeAuthDiscoveryHash() not deterministic: %q != %q", hash1, hash2)
	}

	if len(hash1) != 12 {
		t.Errorf("expected 12 character hash, got %d characters: %q", len(hash1), hash1)
	}
}

func TestComputeAuthDiscoveryHash_OrderIndependent(t *testing.T) {
	auth := policyserver.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "test-client-id",
	}

	// Same patterns in different order should produce same hash.
	patterns1 := []string{"host1.example.com", "host2.example.com", "host3.example.com"}
	patterns2 := []string{"host3.example.com", "host1.example.com", "host2.example.com"}

	hash1 := policyserver.ComputeAuthDiscoveryHash(auth, patterns1)
	hash2 := policyserver.ComputeAuthDiscoveryHash(auth, patterns2)

	if hash1 != hash2 {
		t.Errorf("ComputeAuthDiscoveryHash() should be order-independent: %q != %q", hash1, hash2)
	}
}

func TestComputeAuthDiscoveryHash_ChangesWithPatterns(t *testing.T) {
	auth := policyserver.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "test-client-id",
	}

	patterns1 := []string{"host1.example.com"}
	patterns2 := []string{"host1.example.com", "host2.example.com"}

	hash1 := policyserver.ComputeAuthDiscoveryHash(auth, patterns1)
	hash2 := policyserver.ComputeAuthDiscoveryHash(auth, patterns2)

	if hash1 == hash2 {
		t.Errorf("ComputeAuthDiscoveryHash() should change when patterns change: %q == %q", hash1, hash2)
	}
}

func TestComputeAuthDiscoveryHash_EmptyInputs(t *testing.T) {
	auth := policyserver.BootstrapAuth{}
	var patterns []string

	hash := policyserver.ComputeAuthDiscoveryHash(auth, patterns)

	if len(hash) != 12 {
		t.Errorf("expected 12 character hash even for empty inputs, got %d characters: %q", len(hash), hash)
	}
}

func TestBootstrapAuth_WithOIDC(t *testing.T) {
	cfg := policyserver.PolicyRulesConfig{
		OIDC: policyserver.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			ClientID: "test-client-id.apps.googleusercontent.com",
		},
	}

	auth := cfg.BootstrapAuth()

	if auth.Type != "oidc" {
		t.Errorf("expected type 'oidc', got %q", auth.Type)
	}
	if auth.Issuer != "https://accounts.google.com" {
		t.Errorf("expected issuer 'https://accounts.google.com', got %q", auth.Issuer)
	}
	if auth.ClientID != "test-client-id.apps.googleusercontent.com" {
		t.Errorf("expected client_id 'test-client-id.apps.googleusercontent.com', got %q", auth.ClientID)
	}
	// Should have default scopes
	expectedScopes := []string{"openid", "profile", "email"}
	if len(auth.Scopes) != len(expectedScopes) {
		t.Errorf("expected %d scopes, got %d", len(expectedScopes), len(auth.Scopes))
	}
	for i, scope := range expectedScopes {
		if auth.Scopes[i] != scope {
			t.Errorf("expected scope[%d]=%q, got %q", i, scope, auth.Scopes[i])
		}
	}
}

func TestBootstrapAuth_WithCustomScopes(t *testing.T) {
	cfg := policyserver.PolicyRulesConfig{
		OIDC: policyserver.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			ClientID: "test-client-id",
			Scopes:   []string{"openid", "custom-scope"},
		},
	}

	auth := cfg.BootstrapAuth()

	expectedScopes := []string{"openid", "custom-scope"}
	if len(auth.Scopes) != len(expectedScopes) {
		t.Errorf("expected %d scopes, got %d", len(expectedScopes), len(auth.Scopes))
	}
	for i, scope := range expectedScopes {
		if auth.Scopes[i] != scope {
			t.Errorf("expected scope[%d]=%q, got %q", i, scope, auth.Scopes[i])
		}
	}
}

func TestComputeUnauthDiscoveryHash_Deterministic(t *testing.T) {
	auth := policyserver.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "test-client-id",
		Scopes:   []string{"openid", "profile", "email"},
	}

	hash1 := policyserver.ComputeUnauthDiscoveryHash(auth)
	hash2 := policyserver.ComputeUnauthDiscoveryHash(auth)

	if hash1 != hash2 {
		t.Errorf("ComputeUnauthDiscoveryHash() not deterministic: %q != %q", hash1, hash2)
	}

	if len(hash1) != 12 {
		t.Errorf("expected 12 character hash, got %d characters: %q", len(hash1), hash1)
	}
}

func TestComputeUnauthDiscoveryHash_ChangesWithConfig(t *testing.T) {
	auth1 := policyserver.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "client-id-1",
		Scopes:   []string{"openid", "profile", "email"},
	}

	auth2 := policyserver.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "client-id-2",
		Scopes:   []string{"openid", "profile", "email"},
	}

	hash1 := policyserver.ComputeUnauthDiscoveryHash(auth1)
	hash2 := policyserver.ComputeUnauthDiscoveryHash(auth2)

	if hash1 == hash2 {
		t.Errorf("ComputeUnauthDiscoveryHash() should change when client_id changes: %q == %q", hash1, hash2)
	}
}

func TestComputeUnauthDiscoveryHash_ChangesWithScopes(t *testing.T) {
	auth1 := policyserver.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "test-client-id",
		Scopes:   []string{"openid"},
	}

	auth2 := policyserver.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "test-client-id",
		Scopes:   []string{"openid", "profile"},
	}

	hash1 := policyserver.ComputeUnauthDiscoveryHash(auth1)
	hash2 := policyserver.ComputeUnauthDiscoveryHash(auth2)

	if hash1 == hash2 {
		t.Errorf("ComputeUnauthDiscoveryHash() should change when scopes change: %q == %q", hash1, hash2)
	}
}
