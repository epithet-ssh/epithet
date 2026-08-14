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

func TestValidateReturnsIdentityAndExpiry(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)

	exp := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	claims, err := v.Validate(context.Background(), idp.MintIDToken("alice@example.com", exp))
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", claims.Identity)
	require.WithinDuration(t, exp, claims.ExpiresAt, time.Second)
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
