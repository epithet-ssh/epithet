package principal

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const vectorEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75S vector-comment"

func TestDeriveV1NormativeVector(t *testing.T) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(vectorEd25519))
	require.NoError(t, err)

	got, err := DeriveV1(key, "ubuntu")
	require.NoError(t, err)
	require.Equal(t,
		"epithet-principal-v1-pV-Og_HWXFEBuK01mJV1xsd1VpSny25vP3SwcfikJmg",
		got)
	require.Len(t, got, 64)
}

func TestDeriveV1UsesCanonicalPublicKeyBlob(t *testing.T) {
	a, _, _, _, err := ssh.ParseAuthorizedKey([]byte(vectorEd25519))
	require.NoError(t, err)
	b, _, _, _, err := ssh.ParseAuthorizedKey([]byte(
		"ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75S different-comment\n"))
	require.NoError(t, err)

	principalA, err := DeriveV1(a, "ubuntu")
	require.NoError(t, err)
	principalB, err := DeriveV1(b, "ubuntu")
	require.NoError(t, err)
	require.Equal(t, principalA, principalB)
}

func TestDeriveV1AccountIsByteExact(t *testing.T) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(vectorEd25519))
	require.NoError(t, err)

	lower, err := DeriveV1(key, "ubuntu")
	require.NoError(t, err)
	upper, err := DeriveV1(key, "Ubuntu")
	require.NoError(t, err)
	withNUL, err := DeriveV1(key, "ubuntu\x00")
	require.NoError(t, err)

	require.NotEqual(t, lower, upper)
	require.NotEqual(t, lower, withNUL)
}

func TestDeriveV1RequiresHostKey(t *testing.T) {
	_, err := DeriveV1(nil, "ubuntu")
	require.EqualError(t, err, "host public key is required")
}

func TestV1PreimageFraming(t *testing.T) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(vectorEd25519))
	require.NoError(t, err)

	h := sha256.New()
	for _, field := range [][]byte{[]byte(SchemeV1), key.Marshal(), []byte("ubuntu")} {
		require.NoError(t, writeSSHString(h, field))
	}

	// This complete preimage is a normative byte-level vector, independent of
	// the final digest assertion above.
	want, err := hex.DecodeString(
		"00000014657069746865742d7072696e636970616c2d7631" +
			"000000330000000b7373682d6564323535313900000020" +
			"fef78393255a2818d8fd2cee253f0a1b5fdcc8be2b1c72e35e4e904cb103be52" +
			"000000067562756e7475")
	require.NoError(t, err)

	direct := sha256.Sum256(want)
	require.Equal(t, direct[:], h.Sum(nil))
}
