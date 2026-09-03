package hostid

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateReturnsCanonicalV1ID(t *testing.T) {
	id, err := Generate()
	require.NoError(t, err)
	require.NoError(t, id.Validate())
	require.Len(t, id.String(), len(prefixV1)+encodedSize)
}

func TestParseCanonicalV1ID(t *testing.T) {
	want := prefixV1 + base64.RawURLEncoding.EncodeToString(make([]byte, entropySize))

	got, err := Parse(want)
	require.NoError(t, err)
	require.Equal(t, ID(want), got)
}

func TestParseRejectsMalformedID(t *testing.T) {
	validPayload := base64.RawURLEncoding.EncodeToString(make([]byte, entropySize))
	tests := map[string]string{
		"empty":          "",
		"wrong scheme":   "host-v1-" + validPayload,
		"short payload":  prefixV1 + validPayload[:len(validPayload)-1],
		"long payload":   prefixV1 + validPayload + "A",
		"padded payload": prefixV1 + validPayload + "=",
		"invalid base64": prefixV1 + strings.Repeat("!", encodedSize),
		"trailing space": prefixV1 + validPayload[:len(validPayload)-1] + " ",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(value)
			require.Error(t, err)
		})
	}
}

func TestTextRoundTrip(t *testing.T) {
	want, err := Generate()
	require.NoError(t, err)

	text, err := want.MarshalText()
	require.NoError(t, err)

	var got ID
	require.NoError(t, got.UnmarshalText(text))
	require.Equal(t, want, got)
}

func TestZeroIDCannotBeMarshaled(t *testing.T) {
	_, err := (ID("")).MarshalText()
	require.Error(t, err)
}
