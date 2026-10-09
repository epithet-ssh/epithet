package principal

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateHostReturnsCanonicalRealm(t *testing.T) {
	realm, err := GenerateHostRealm()
	require.NoError(t, err)
	require.NoError(t, realm.Validate())
	require.True(t, realm.IsGeneratedHost())
	require.Len(t, realm.String(), len(generatedHostPrefixV1)+encodedSize)
}

func TestParseNamedRealm(t *testing.T) {
	for _, value := range []string{"floop", "Floop", "AI-worker-Pool-1", "prod.ssh_workers"} {
		t.Run(value, func(t *testing.T) {
			realm, err := ParseNamedRealm(value)
			require.NoError(t, err)
			require.Equal(t, Realm(value), realm)
			require.False(t, realm.IsGeneratedHost())
		})
	}
}

func TestParseRejectsMalformedNamedRealm(t *testing.T) {
	for name, value := range map[string]string{
		"empty":             "",
		"leading hyphen":    "-floop",
		"trailing hyphen":   "floop-",
		"space":             "ai worker",
		"colon":             "team:one",
		"unicode":           "flööp",
		"reserved no colon": GeneratedHostSchemeV1,
		"too long":          strings.Repeat("a", maxNamedLength+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRealm(value)
			require.Error(t, err)
		})
	}
}

func TestParseGeneratedHostRealm(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString(make([]byte, entropySize))
	want := generatedHostPrefixV1 + payload

	got, err := ParseRealm(want)
	require.NoError(t, err)
	require.Equal(t, Realm(want), got)
	require.True(t, got.IsGeneratedHost())
	_, err = ParseNamedRealm(want)
	require.ErrorContains(t, err, "reserved")
}

func TestParseRejectsMalformedGeneratedRealm(t *testing.T) {
	for _, value := range []string{
		GeneratedHostSchemeV1,
		generatedHostPrefixV1 + "short",
		generatedHostPrefixV1 + strings.Repeat("!", encodedSize),
	} {
		_, err := ParseRealm(value)
		require.Error(t, err)
	}
}

func TestTextRoundTrip(t *testing.T) {
	want, err := GenerateHostRealm()
	require.NoError(t, err)

	text, err := want.MarshalText()
	require.NoError(t, err)

	var got Realm
	require.NoError(t, got.UnmarshalText(text))
	require.Equal(t, want, got)
}
