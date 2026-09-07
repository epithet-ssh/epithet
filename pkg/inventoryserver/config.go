package inventoryserver

import (
	"fmt"

	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// ServerConfig contains inventory-owned authentication settings loaded at startup.
type ServerConfig struct {
	CAPublicKey string     `yaml:"ca_pubkey" json:"ca_pubkey"`
	OIDC        OIDCConfig `yaml:"oidc" json:"oidc"`
}

// Validate checks that the ServerConfig is valid.
func (c *ServerConfig) Validate() error {
	if c.CAPublicKey == "" {
		return fmt.Errorf("ca_pubkey is required")
	}

	if c.OIDC.Issuer == "" {
		return fmt.Errorf("oidc.issuer is required")
	}

	if c.OIDC.ClientID == "" {
		return fmt.Errorf("oidc.client_id is required")
	}

	_, _, err := oidc.ResolveIdentity(c.OIDC.Issuer, c.OIDC.IdentityMode, c.OIDC.UserIDClaim)
	return err
}

// BootstrapAuth returns the auth configuration for the bootstrap endpoint.
func (c *ServerConfig) BootstrapAuth() wire.AuthConfig {
	return wire.AuthConfig{
		Issuer:       c.OIDC.Issuer,
		ClientID:     c.OIDC.ClientID,
		ClientSecret: c.OIDC.ClientSecret,
	}
}

// OIDCConfig represents OIDC configuration for token validation
type OIDCConfig struct {
	IdentityMode oidc.IdentityMode `yaml:"identity_mode,omitempty" json:"identity_mode,omitempty"`
	UserIDClaim  string            `yaml:"user_id_claim,omitempty" json:"user_id_claim,omitempty"`
	Issuer       string            `yaml:"issuer" json:"issuer"`
	ClientID     string            `yaml:"client_id" json:"client_id"`
	ClientSecret string            `yaml:"client_secret,omitempty" json:"client_secret,omitempty"` // Optional, for confidential clients
}
