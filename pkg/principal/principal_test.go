package principal

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

const vectorDomain = Domain("ai-worker-pool-1")

func TestDeriveV1NormativeVector(t *testing.T) {
	got, err := DeriveV1(vectorDomain, "ubuntu")
	require.NoError(t, err)
	require.Equal(t,
		"epithet-principal-v1-MTgFaDsSaL2IM0v4UljbMjiyxMUQiOK9KymVavQ2Y14",
		got)
	require.Len(t, got, 64)
}

func TestDeriveV1AccountIsByteExact(t *testing.T) {
	lower, err := DeriveV1(vectorDomain, "ubuntu")
	require.NoError(t, err)
	upper, err := DeriveV1(vectorDomain, "Ubuntu")
	require.NoError(t, err)
	withNUL, err := DeriveV1(vectorDomain, "ubuntu\x00")
	require.NoError(t, err)

	require.NotEqual(t, lower, upper)
	require.NotEqual(t, lower, withNUL)
}

func TestDeriveV1RequiresValidDomain(t *testing.T) {
	_, err := DeriveV1("", "ubuntu")
	require.ErrorContains(t, err, "invalid principal domain")
}

func TestV1PreimageFraming(t *testing.T) {
	h := sha256.New()
	for _, field := range [][]byte{[]byte(SchemeV1), []byte(vectorDomain), []byte("ubuntu")} {
		require.NoError(t, writeSSHString(h, field))
	}

	// This complete preimage is a normative byte-level vector, independent of
	// the final digest assertion above.
	want, err := hex.DecodeString(
		"00000014657069746865742d7072696e636970616c2d7631" +
			"0000001061692d776f726b65722d706f6f6c2d31" +
			"000000067562756e7475")
	require.NoError(t, err)

	direct := sha256.Sum256(want)
	require.Equal(t, direct[:], h.Sum(nil))
}
