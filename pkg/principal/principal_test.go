package principal

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/hostid"
	"github.com/stretchr/testify/require"
)

const vectorHostID = hostid.ID("epithet-host-v1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")

func TestDeriveV1NormativeVector(t *testing.T) {
	got, err := DeriveV1(vectorHostID, "ubuntu")
	require.NoError(t, err)
	require.Equal(t,
		"epithet-principal-v1-1G2FFzyyJShb63-XQoyRcIgz0rVX62Ob9KhnKc5k90o",
		got)
	require.Len(t, got, 64)
}

func TestDeriveV1AccountIsByteExact(t *testing.T) {
	lower, err := DeriveV1(vectorHostID, "ubuntu")
	require.NoError(t, err)
	upper, err := DeriveV1(vectorHostID, "Ubuntu")
	require.NoError(t, err)
	withNUL, err := DeriveV1(vectorHostID, "ubuntu\x00")
	require.NoError(t, err)

	require.NotEqual(t, lower, upper)
	require.NotEqual(t, lower, withNUL)
}

func TestDeriveV1RequiresValidHostID(t *testing.T) {
	_, err := DeriveV1("", "ubuntu")
	require.ErrorContains(t, err, "invalid host ID")
}

func TestV1PreimageFraming(t *testing.T) {
	h := sha256.New()
	for _, field := range [][]byte{[]byte(SchemeV1), []byte(vectorHostID), []byte("ubuntu")} {
		require.NoError(t, writeSSHString(h, field))
	}

	// This complete preimage is a normative byte-level vector, independent of
	// the final digest assertion above.
	want, err := hex.DecodeString(
		"00000014657069746865742d7072696e636970616c2d7631" +
			"0000003b657069746865742d686f73742d76312d414145434177514642676349" +
			"43516f4c4441304f4478415245684d554652595847426b6147787764486838" +
			"000000067562756e7475")
	require.NoError(t, err)

	direct := sha256.Sum256(want)
	require.Equal(t, direct[:], h.Sum(nil))
}
