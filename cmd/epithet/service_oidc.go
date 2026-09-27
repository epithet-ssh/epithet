package main

import "github.com/epithet-ssh/epithet/pkg/identity/oidc"

// ServiceOIDCConfig holds OIDC configuration for the issuing and control services.
type ServiceOIDCConfig struct {
	IdentityMode oidc.IdentityMode `help:"Identity mode: stable-id (default) or verified-email" name:"identity-mode" env:"EPITHET_OIDC_IDENTITY_MODE"`
	UserIDClaim  string            `help:"JWT claim mapped to inventory id in stable-id mode, including email without verification checks (default: oid for Microsoft Entra, sub otherwise)" name:"user-id-claim" env:"EPITHET_OIDC_USER_ID_CLAIM"`
	Issuer       string            `help:"OIDC issuer URL" name:"issuer"`
	ClientID     string            `help:"OIDC client ID" name:"client-id"`
	ClientSecret string            `help:"OIDC client secret (for confidential clients)" name:"client-secret"`
}
