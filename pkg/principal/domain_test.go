package principal

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateHostReturnsCanonicalDomain(t *testing.T) {
	domain, err := GenerateHostDomain()
	require.NoError(t, err)
	require.NoError(t, domain.Validate())
	require.True(t, domain.IsGeneratedHost())
	require.Len(t, domain.String(), len(generatedHostPrefixV1)+encodedSize)
}

func TestParseNamedDomain(t *testing.T) {
	for _, value := range []string{"floop", "ai-worker-pool-1", "prod.ssh_workers"} {
		t.Run(value, func(t *testing.T) {
			domain, err := ParseNamedDomain(value)
			require.NoError(t, err)
			require.Equal(t, Domain(value), domain)
			require.False(t, domain.IsGeneratedHost())
		})
	}
}

func TestParseRejectsMalformedNamedDomain(t *testing.T) {
	for name, value := range map[string]string{
		"empty":             "",
		"uppercase":         "Floop",
		"leading hyphen":    "-floop",
		"trailing hyphen":   "floop-",
		"space":             "ai worker",
		"colon":             "team:one",
		"unicode":           "flööp",
		"reserved no colon": GeneratedHostSchemeV1,
		"too long":          strings.Repeat("a", maxNamedLength+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDomain(value)
			require.Error(t, err)
		})
	}
}

func TestParseGeneratedHostDomain(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString(make([]byte, entropySize))
	want := generatedHostPrefixV1 + payload

	got, err := ParseDomain(want)
	require.NoError(t, err)
	require.Equal(t, Domain(want), got)
	require.True(t, got.IsGeneratedHost())
	_, err = ParseNamedDomain(want)
	require.ErrorContains(t, err, "reserved")
}

func TestParseRejectsMalformedGeneratedDomain(t *testing.T) {
	for _, value := range []string{
		GeneratedHostSchemeV1,
		generatedHostPrefixV1 + "short",
		generatedHostPrefixV1 + strings.Repeat("!", encodedSize),
	} {
		_, err := ParseDomain(value)
		require.Error(t, err)
	}
}

func TestTextRoundTrip(t *testing.T) {
	want, err := GenerateHostDomain()
	require.NoError(t, err)

	text, err := want.MarshalText()
	require.NoError(t, err)

	var got Domain
	require.NoError(t, got.UnmarshalText(text))
	require.Equal(t, want, got)
}
