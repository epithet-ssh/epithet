package policyserver_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

func TestServerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     policyserver.ServerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: policyserver.ServerConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
			},
			wantErr: false,
		},
		{
			name: "missing ca_public_key",
			cfg: policyserver.ServerConfig{
				OIDC: policyserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
			},
			wantErr: true,
		},
		{
			name: "missing issuer",
			cfg: policyserver.ServerConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{ClientID: "client-id"},
			},
			wantErr: true,
		},
		{
			name: "missing client_id",
			cfg: policyserver.ServerConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        policyserver.OIDCConfig{Issuer: "https://issuer"},
			},
			wantErr: true,
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

func TestServerConfig_BootstrapAuth(t *testing.T) {
	cfg := policyserver.ServerConfig{
		OIDC: policyserver.OIDCConfig{
			Issuer:       "https://accounts.google.com",
			ClientID:     "test-client-id.apps.googleusercontent.com",
			ClientSecret: "shh",
		},
	}

	auth := cfg.BootstrapAuth()

	if auth.Issuer != "https://accounts.google.com" {
		t.Errorf("expected issuer 'https://accounts.google.com', got %q", auth.Issuer)
	}
	if auth.ClientID != "test-client-id.apps.googleusercontent.com" {
		t.Errorf("expected client_id 'test-client-id.apps.googleusercontent.com', got %q", auth.ClientID)
	}
	if auth.ClientSecret != "shh" {
		t.Errorf("expected client_secret 'shh', got %q", auth.ClientSecret)
	}
}

func TestBootstrapAdvertisesEffectiveUserIDClaim(t *testing.T) {
	for _, tc := range []struct{ issuer, override, want string }{
		{"https://accounts.google.com", "", "sub"},
		{"https://login.microsoftonline.com/tenant/v2.0", "", "oid"},
		{"https://login.microsoftonline.com/tenant/v2.0", "sub", "sub"},
		{"https://idp.example", "directory_id", "directory_id"},
	} {
		cfg := policyserver.ServerConfig{OIDC: policyserver.OIDCConfig{Issuer: tc.issuer, UserIDClaim: tc.override}}
		if got := cfg.BootstrapAuth().UserIDClaim; got != tc.want {
			t.Errorf("issuer %s override %s: got %s want %s", tc.issuer, tc.override, got, tc.want)
		}
	}
}
