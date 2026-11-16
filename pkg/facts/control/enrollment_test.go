package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestEnrollmentWithECDSAControlKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(key, "")
	require.NoError(t, err)
	authority, err := newEnrollmentAuthority(sshcert.RawPrivateKey(pem.EncodeToMemory(block)))
	require.NoError(t, err)
	raw, _, err := authority.issue("provisioner", 60)
	require.NoError(t, err)
	subject, err := authority.verify(raw)
	require.NoError(t, err)
	require.Equal(t, "provisioner", subject)
}

func TestEnrollmentClaimsAndLifetime(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	authority, err := newEnrollmentAuthority(key)
	require.NoError(t, err)
	for _, seconds := range []int64{1, 86401, 90 * 24 * 3600} {
		raw, expiry, err := authority.issue("production-provisioner", seconds)
		require.NoError(t, err)
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
		require.NoError(t, err)
		var claims map[string]any
		require.NoError(t, json.Unmarshal(payload, &claims))
		require.Len(t, claims, 3)
		require.Equal(t, enrollmentAudience, claims["aud"])
		require.Equal(t, "production-provisioner", claims["sub"])
		require.Equal(t, float64(expiry.Unix()), claims["exp"])
		require.WithinDuration(t, time.Now().Add(time.Duration(seconds)*time.Second), expiry, time.Second)
		sub, err := authority.verify(raw)
		require.NoError(t, err)
		require.Equal(t, "production-provisioner", sub)
		for _, audience := range []string{serviceauth.Audience, serviceauth.InventoryAudience, serviceauth.DirectoryAudience} {
			verifier, err := serviceauth.NewVerifierFor(public, audience)
			require.NoError(t, err)
			request := httptest.NewRequest("POST", "https://inventory/inventory/records", nil)
			request.Header.Set("Authorization", "Bearer "+raw)
			require.Error(t, verifier.Verify(request, nil), "enrollment cannot authorize internal requests")
		}
	}
	for _, tc := range []struct {
		subject string
		seconds int64
	}{{"", 60}, {"principal", 0}, {"principal", -1}, {"principal", math.MaxInt64}} {
		_, _, err := authority.issue(tc.subject, tc.seconds)
		require.Error(t, err)
	}
}

func TestEnrollmentVerificationRejectsOtherCredentials(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	authority, err := newEnrollmentAuthority(key)
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing audience", func(c map[string]any) { delete(c, "aud") }},
		{"wrong audience", func(c map[string]any) { c["aud"] = serviceauth.InventoryAudience }},
		{"missing expiration", func(c map[string]any) { delete(c, "exp") }},
		{"null expiration", func(c map[string]any) { c["exp"] = nil }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Unix() - 1 }},
		{"at expiration", func(c map[string]any) { c["exp"] = time.Now().Unix() }},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }},
		{"empty subject", func(c map[string]any) { c["sub"] = "" }},
		{"invalid subject", func(c map[string]any) { c["sub"] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"aud": enrollmentAudience, "exp": time.Now().Unix() + 60, "sub": "provisioner"}
			tc.change(claims)
			raw, err := jwt.Signed(authority.signer).Claims(claims).Serialize()
			require.NoError(t, err)
			_, err = authority.verify(raw)
			require.Error(t, err)
		})
	}
	_, otherKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	other, err := newEnrollmentAuthority(otherKey)
	require.NoError(t, err)
	wrong, _, err := other.issue("provisioner", 60)
	require.NoError(t, err)
	_, err = authority.verify(wrong)
	require.Error(t, err)
	raw, _, err := authority.issue("provisioner", 60)
	require.NoError(t, err)
	parts := strings.Split(raw, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"epithet-enrollment","exp":9999999999,"sub":"forged"}`))
	_, err = authority.verify(strings.Join(parts, "."))
	require.Error(t, err)
	for _, audience := range []string{serviceauth.Audience, serviceauth.InventoryAudience, serviceauth.DirectoryAudience} {
		signer, err := serviceauth.NewSignerFor(key, audience)
		require.NoError(t, err)
		request := httptest.NewRequest("POST", "https://control/manage/host", nil)
		require.NoError(t, signer.AuthorizeActor(request, nil, "provisioner"))
		_, err = authority.verify(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		require.Error(t, err)
	}
}
