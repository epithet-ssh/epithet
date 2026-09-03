package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const hostVectorID = "epithet-host-v1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n"

func TestHostAuthorizedPrincipalsNormativeVector(t *testing.T) {
	path := writeHostID(t, "host-id", hostVectorID)
	cmd := HostAuthorizedPrincipalsCLI{HostIDFile: path, Account: "ubuntu"}

	var out bytes.Buffer
	require.NoError(t, cmd.writeAuthorizedPrincipals(&out))
	require.Equal(t,
		"epithet-principal-v1-1G2FFzyyJShb63-XQoyRcIgz0rVX62Ob9KhnKc5k90o\n",
		out.String())
}

func TestHostAuthorizedPrincipalsSupportsMigration(t *testing.T) {
	path := writeHostID(t, "host-id", hostVectorID)
	cmd := HostAuthorizedPrincipalsCLI{
		HostIDFile:        path,
		AcceptAccountName: true,
		Account:           "ubuntu",
	}

	var out bytes.Buffer
	require.NoError(t, cmd.writeAuthorizedPrincipals(&out))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Equal(t, []string{
		"epithet-principal-v1-1G2FFzyyJShb63-XQoyRcIgz0rVX62Ob9KhnKc5k90o",
		"ubuntu",
	}, lines)
}

func TestHostAuthorizedPrincipalsRejectsMultipleIDsInOneFile(t *testing.T) {
	path := writeHostID(t, "host-id", hostVectorID+hostVectorID)
	cmd := HostAuthorizedPrincipalsCLI{HostIDFile: path, Account: "ubuntu"}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "must contain exactly one line")
}

func TestHostAuthorizedPrincipalsRejectsLiteralAccountWithWhitespace(t *testing.T) {
	path := writeHostID(t, "host-id", hostVectorID)
	cmd := HostAuthorizedPrincipalsCLI{
		HostIDFile:        path,
		AcceptAccountName: true,
		Account:           "not\na-principal",
	}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "cannot be emitted")
}

func TestHostAuthorizedPrincipalsRejectsMalformedID(t *testing.T) {
	path := writeHostID(t, "host-id", "not-a-host-id\n")
	cmd := HostAuthorizedPrincipalsCLI{HostIDFile: path, Account: "ubuntu"}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "parsing host ID")
}

func writeHostID(t *testing.T, name, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(value), 0o600))
	return path
}
