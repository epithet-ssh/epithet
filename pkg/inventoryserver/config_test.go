package inventoryserver_test

import (
	"encoding/json"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventoryserver"
	"github.com/stretchr/testify/require"
)

func TestServerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     inventoryserver.ServerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: inventoryserver.ServerConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        inventoryserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
			},
			wantErr: false,
		},
		{
			name: "missing ca_public_key",
			cfg: inventoryserver.ServerConfig{
				OIDC: inventoryserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client-id"},
			},
			wantErr: true,
		},
		{
			name: "missing issuer",
			cfg: inventoryserver.ServerConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        inventoryserver.OIDCConfig{ClientID: "client-id"},
			},
			wantErr: true,
		},
		{
			name: "missing client_id",
			cfg: inventoryserver.ServerConfig{
				CAPublicKey: "ssh-ed25519 AAAA...",
				OIDC:        inventoryserver.OIDCConfig{Issuer: "https://issuer"},
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

func TestServerConfig_BootstrapAuth(t *testing.T) {
	cfg := inventoryserver.ServerConfig{
		OIDC: inventoryserver.OIDCConfig{
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

func TestBootstrapOmitsInventoryMapping(t *testing.T) {
	cfg := inventoryserver.ServerConfig{OIDC: inventoryserver.OIDCConfig{Issuer: "https://issuer", IdentityMode: oidc.StableID, UserIDClaim: "email"}}
	encoded, err := json.Marshal(cfg.BootstrapAuth())
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "user_id_claim")
	require.NotContains(t, string(encoded), "identity_mode")
}

func TestServerConfigIdentitySettings(t *testing.T) {
	for _, tc := range []struct {
		mode  oidc.IdentityMode
		claim string
		valid bool
	}{
		{"", "email", true}, {oidc.StableID, "email", true}, {oidc.VerifiedEmail, "", true},
		{oidc.VerifiedEmail, "email", false}, {"typo", "", false},
	} {
		cfg := inventoryserver.ServerConfig{CAPublicKey: "key", OIDC: inventoryserver.OIDCConfig{Issuer: "https://issuer", ClientID: "client", IdentityMode: tc.mode, UserIDClaim: tc.claim}}
		if tc.valid {
			require.NoError(t, cfg.Validate())
		} else {
			require.Error(t, cfg.Validate())
		}
	}
}
