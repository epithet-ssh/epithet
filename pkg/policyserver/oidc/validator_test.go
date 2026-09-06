package oidc

import (
	"context"
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
