package oidc

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/stretchr/testify/require"
)

func newValidator(t *testing.T, idp *oidctest.IdP) *Validator {
	v, err := NewValidator(context.Background(), Config{
		Issuer:   idp.Issuer(),
		ClientID: oidctest.ClientID,
	})
	require.NoError(t, err)
	return v
}

func TestValidateReturnsSubjectIssuerAndExpiry(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)

	exp := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	claims, err := v.Validate(context.Background(), idp.MintIDToken("alice@example.com", exp))
	require.NoError(t, err)
	require.Equal(t, oidctest.Subject("alice@example.com"), claims.Subject)
	require.Equal(t, idp.Issuer(), claims.Issuer)
	require.Equal(t, claims.Subject, claims.UserID)
	require.WithinDuration(t, exp, claims.ExpiresAt, time.Second)
}

func TestValidateSubjectDoesNotDependOnEmail(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)
	for _, tc := range []struct {
		name   string
		claims map[string]any
	}{
		{"unverified-victim-email", map[string]any{"email": "victim@example.com", "email_verified": false}},
		{"verified-victim-email", map[string]any{"email": "victim@example.com", "email_verified": true}},
		{"no-email", map[string]any{"email": nil, "email_verified": nil}},
		{"invalid-email-types", map[string]any{"email": 123, "email_verified": "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := idp.MintIDTokenWithClaims("attacker@example.com", time.Now().Add(time.Minute), tc.claims)
			claims, err := v.Validate(context.Background(), token)
			require.NoError(t, err)
			require.Equal(t, oidctest.Subject("attacker@example.com"), claims.Subject)
		})
	}
}

func TestValidateRejectsMissingOrMalformedSubject(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)
	for _, subject := range []any{nil, "", 123, []string{"alice"}} {
		token := idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), map[string]any{"sub": subject})
		_, err := v.Validate(context.Background(), token)
		require.Error(t, err, "subject: %#v", subject)
	}
}

func TestValidateRejectsWrongIssuerWithSameSigningKeyAndSubject(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)
	token := idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), map[string]any{"iss": "https://another-issuer.example"})
	_, err := v.Validate(context.Background(), token)
	require.Error(t, err)
}

func TestValidateRejectsExpiredToken(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)
	_, err := v.Validate(context.Background(), idp.MintIDToken("alice@example.com", time.Now().Add(-time.Minute)))
	require.Error(t, err)
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)
	tok := idp.MintIDTokenWithAudience("alice@example.com", "someone-else", time.Now().Add(time.Minute))
	_, err := v.Validate(context.Background(), tok)
	require.Error(t, err)
}

func TestNewValidatorRequiresClientID(t *testing.T) {
	idp := oidctest.New(t)
	_, err := NewValidator(context.Background(), Config{Issuer: idp.Issuer()})
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_id")
}

func TestUserIDClaimDefaultsAndOverride(t *testing.T) {
	for _, tc := range []struct{ issuer, want string }{
		{"https://accounts.google.com", "sub"},
		{"https://company.okta.com/oauth2/default", "sub"},
		{"https://idp.example.com", "sub"},
		{"https://login.microsoftonline.com/tenant/v2.0", "oid"},
		{"https://login.microsoftonline.us/tenant/v2.0", "oid"},
		{"https://login.partner.microsoftonline.cn/tenant/v2.0", "oid"},
		{"https://login.chinacloudapi.cn/tenant/v2.0", "oid"},
		{"https://sts.windows.net/tenant/", "oid"},
		{"https://login.microsoftonline.com/common/v2.0", "sub"},
		{"https://login.microsoftonline.com/organizations/v2.0", "sub"},
		{"https://login.microsoftonline.com/consumers/v2.0", "sub"},
		{"https://login.microsoftonline.com/", "sub"},
		{"https://login.microsoftonline.com/tenant/not-v2", "sub"},
		{"https://login.microsoftonline.com.evil.example/tenant/v2.0", "sub"},
		{"https://evil.example/login.microsoftonline.com/tenant/v2.0", "sub"},
		{"https://login.microsoftonline.com@evil.example/tenant/v2.0", "sub"},
		{"http://login.microsoftonline.com/tenant/v2.0", "sub"},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			require.Equal(t, tc.want, ResolveUserIDClaim(tc.issuer, ""))
			require.Equal(t, "custom_id", ResolveUserIDClaim(tc.issuer, "custom_id"))
			require.Equal(t, "sub", ResolveUserIDClaim(tc.issuer, "sub"))
		})
	}
}

func TestValidateMappedUserID(t *testing.T) {
	idp := oidctest.New(t)
	for _, key := range []string{"oid", "https://example.com/user_id"} {
		t.Run(key, func(t *testing.T) {
			v, err := NewValidator(context.Background(), Config{
				Issuer: idp.Issuer(), ClientID: oidctest.ClientID, UserIDClaim: key,
			})
			require.NoError(t, err)
			for _, tc := range []struct {
				name  string
				value any
				valid bool
			}{
				{"valid", "Directory-ID", true},
				{"absent-or-null", nil, false},
				{"empty", "", false},
				{"number", 123, false},
				{"boolean", true, false},
				{"array", []string{"Directory-ID"}, false},
				{"object", map[string]string{"id": "Directory-ID"}, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					token := idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), map[string]any{key: tc.value})
					claims, err := v.Validate(context.Background(), token)
					if !tc.valid {
						require.ErrorContains(t, err, "must be a nonempty string")
						require.Nil(t, claims, "must not fall back to sub or email")
						return
					}
					require.NoError(t, err)
					require.Equal(t, "Directory-ID", claims.UserID)
					require.Equal(t, oidctest.Subject("alice@example.com"), claims.Subject)
				})
			}
			for _, overrides := range []map[string]any{
				{"iss": "https://wrong-issuer.example"},
				{"aud": "wrong-client"},
				{"sub": ""},
				{"exp": time.Now().Add(-time.Minute).Unix()},
			} {
				overrides[key] = "Directory-ID"
				token := idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), overrides)
				_, err := v.Validate(context.Background(), token)
				require.Error(t, err, "mapping must not bypass standard validation")
			}
		})
	}
}

func TestIdentityModeResolution(t *testing.T) {
	for _, tc := range []struct {
		mode      IdentityMode
		claim     string
		wantMode  IdentityMode
		wantClaim string
		invalid   bool
	}{
		{"", "", StableID, "sub", false},
		{StableID, "", StableID, "sub", false},
		{"", "email", StableID, "email", false},
		{StableID, "custom_id", StableID, "custom_id", false},
		{VerifiedEmail, "", VerifiedEmail, "email", false},
		{VerifiedEmail, "email", "", "", true},
		{VerifiedEmail, "sub", "", "", true},
		{"invalid", "", "", "", true},
	} {
		mode, claim, err := ResolveIdentity("https://issuer.example", tc.mode, tc.claim)
		if tc.invalid {
			require.Error(t, err)
			_, err = NewValidator(context.Background(), Config{Issuer: "https://invalid.invalid", ClientID: "client", IdentityMode: tc.mode, UserIDClaim: tc.claim})
			require.ErrorContains(t, err, "mode") // Config rejected before discovery.
		} else {
			require.NoError(t, err)
			require.Equal(t, tc.wantMode, mode)
			require.Equal(t, tc.wantClaim, claim)
		}
	}
}

func TestEmailIdentityModes(t *testing.T) {
	idp := oidctest.New(t)
	otherIDP := oidctest.New(t)
	for _, mode := range []IdentityMode{VerifiedEmail, StableID} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, IdentityMode: mode}
			if mode == StableID {
				cfg.UserIDClaim = "email"
			}
			v, err := NewValidator(context.Background(), cfg)
			require.NoError(t, err)
			_, err = v.Validate(context.Background(), otherIDP.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), map[string]any{"iss": idp.Issuer()}))
			require.Error(t, err, "claims with an untrusted signature must fail")
			for _, tc := range []struct {
				name                          string
				email, verified               any
				validEmail, validVerification bool
			}{
				{"verified", "Alice@Example.com", true, true, true},
				{"false", "Alice@Example.com", false, true, false},
				{"absent", "Alice@Example.com", nil, true, false},
				{"null", "Alice@Example.com", json.RawMessage("null"), true, false},
				{"string", "Alice@Example.com", "true", true, false},
				{"number", "Alice@Example.com", 1, true, false},
				{"array", "Alice@Example.com", []bool{true}, true, false},
				{"object", "Alice@Example.com", map[string]bool{"value": true}, true, false},
				{"no-email", nil, true, false, true},
				{"null-email", json.RawMessage("null"), true, false, true},
				{"empty-email", "", true, false, true},
				{"numeric-email", 42, true, false, true},
				{"array-email", []string{"alice@example.com"}, true, false, true},
				{"boolean-email", true, true, false, true},
				{"object-email", map[string]string{"value": "alice@example.com"}, true, false, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					token := idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), map[string]any{"email": tc.email, "email_verified": tc.verified})
					claims, err := v.Validate(context.Background(), token)
					if !tc.validEmail || (mode == VerifiedEmail && !tc.validVerification) {
						require.Error(t, err)
						require.Nil(t, claims)
						return
					}
					require.NoError(t, err)
					require.Equal(t, tc.email, claims.UserID) // Exact case preserved.
					require.Equal(t, oidctest.Subject("alice@example.com"), claims.Subject)
				})
			}
			for _, overrides := range []map[string]any{
				{"iss": "https://wrong.example"}, {"aud": "wrong"}, {"sub": nil}, {"exp": time.Now().Add(-time.Minute).Unix()},
			} {
				_, err := v.Validate(context.Background(), idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), overrides))
				require.Error(t, err)
			}
		})
	}
}
