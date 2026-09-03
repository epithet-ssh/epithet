package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const hostVectorEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75S host-comment\n"

func TestHostAuthorizedPrincipalsNormativeVector(t *testing.T) {
	path := writeHostPublicKey(t, "host_key.pub", []byte(hostVectorEd25519))
	cmd := HostAuthorizedPrincipalsCLI{HostKeys: []string{path}, Account: "ubuntu"}

	var out bytes.Buffer
	require.NoError(t, cmd.writeAuthorizedPrincipals(&out))
	require.Equal(t,
		"epithet-principal-v1-pV-Og_HWXFEBuK01mJV1xsd1VpSny25vP3SwcfikJmg\n",
		out.String())
}

func TestHostAuthorizedPrincipalsSupportsRotationAndMigration(t *testing.T) {
	first := writeHostPublicKey(t, "first.pub", []byte(hostVectorEd25519))
	second := writeHostPublicKey(t, "second.pub", generateHostPublicKey(t))
	// Include first twice to verify duplicate key inputs emit one principal.
	cmd := HostAuthorizedPrincipalsCLI{
		HostKeys:          []string{first, second, first},
		AcceptAccountName: true,
		Account:           "ubuntu",
	}

	var out bytes.Buffer
	require.NoError(t, cmd.writeAuthorizedPrincipals(&out))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 3)
	require.Equal(t, "epithet-principal-v1-pV-Og_HWXFEBuK01mJV1xsd1VpSny25vP3SwcfikJmg", lines[0])
	require.Contains(t, lines[1], "epithet-principal-v1-")
	require.Equal(t, "ubuntu", lines[2])
}

func TestHostAuthorizedPrincipalsRejectsMultipleKeysInOneFile(t *testing.T) {
	path := writeHostPublicKey(t, "host_keys.pub", []byte(hostVectorEd25519+hostVectorEd25519))
	cmd := HostAuthorizedPrincipalsCLI{HostKeys: []string{path}, Account: "ubuntu"}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "contains more than one key")
}

func TestHostAuthorizedPrincipalsRejectsLiteralAccountWithWhitespace(t *testing.T) {
	path := writeHostPublicKey(t, "host_key.pub", []byte(hostVectorEd25519))
	cmd := HostAuthorizedPrincipalsCLI{
		HostKeys:          []string{path},
		AcceptAccountName: true,
		Account:           "not\na-principal",
	}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "cannot be emitted")
}

func writeHostPublicKey(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func generateHostPublicKey(t *testing.T) []byte {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	return ssh.MarshalAuthorizedKey(key)
}
