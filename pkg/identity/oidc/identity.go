package oidc

import "fmt"

// IdentityMode defines how a verified ID token maps to an inventory user.
type IdentityMode string

const (
	StableID      IdentityMode = "stable-id"
	VerifiedEmail IdentityMode = "verified-email"
)

// ResolveIdentity validates identity settings without network access. Empty mode
// defaults to stable-id. Claim overrides, including email, are administrator
// choices and receive no special email-verification checks in stable-id mode.
func ResolveIdentity(issuer string, mode IdentityMode, override string) (IdentityMode, string, error) {
	if mode == "" {
		mode = StableID
	}
	switch mode {
	case StableID:
		return mode, ResolveUserIDClaim(issuer, override), nil
	case VerifiedEmail:
		if override != "" {
			return "", "", fmt.Errorf("user-id-claim cannot be set in verified-email mode; this mode always uses email")
		}
		return mode, "email", nil
	default:
		return "", "", fmt.Errorf("unknown identity-mode %q: expected stable-id or verified-email", mode)
	}
}
