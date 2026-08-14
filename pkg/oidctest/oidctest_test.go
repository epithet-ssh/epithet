package oidctest

import (
	"context"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
)

func TestMintedTokenVerifiesAgainstJWKS(t *testing.T) {
	idp := New(t)

	provider, err := gooidc.NewProvider(context.Background(), idp.Issuer())
	require.NoError(t, err)

	verifier := provider.Verifier(&gooidc.Config{ClientID: ClientID})
	tok := idp.MintIDToken("alice@example.com", time.Now().Add(5*time.Minute))

	idToken, err := verifier.Verify(context.Background(), tok)
	require.NoError(t, err)

	var claims struct {
		Email string `json:"email"`
	}
	require.NoError(t, idToken.Claims(&claims))
	require.Equal(t, "alice@example.com", claims.Email)
}

func TestExpiredTokenFailsVerification(t *testing.T) {
	idp := New(t)
	provider, err := gooidc.NewProvider(context.Background(), idp.Issuer())
	require.NoError(t, err)
	verifier := provider.Verifier(&gooidc.Config{ClientID: ClientID})

	tok := idp.MintIDToken("alice@example.com", time.Now().Add(-1*time.Minute))
	_, err = verifier.Verify(context.Background(), tok)
	require.Error(t, err)
}
