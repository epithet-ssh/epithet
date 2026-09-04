package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const vectorDomain = "ai-worker-pool-1\n"

func TestHostAuthorizedPrincipalsNormativeVector(t *testing.T) {
	path := writeDomain(t, "domain", vectorDomain)
	cmd := HostAuthorizedPrincipalsCLI{DomainFile: path, Account: "ubuntu"}

	var out bytes.Buffer
	require.NoError(t, cmd.writeAuthorizedPrincipals(&out))
	require.Equal(t,
		"epithet-principal-v1-MTgFaDsSaL2IM0v4UljbMjiyxMUQiOK9KymVavQ2Y14\n",
		out.String())
}

func TestHostAuthorizedPrincipalsSupportsMigration(t *testing.T) {
	path := writeDomain(t, "domain", vectorDomain)
	cmd := HostAuthorizedPrincipalsCLI{
		DomainFile:        path,
		AcceptAccountName: true,
		Account:           "ubuntu",
	}

	var out bytes.Buffer
	require.NoError(t, cmd.writeAuthorizedPrincipals(&out))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Equal(t, []string{
		"epithet-principal-v1-MTgFaDsSaL2IM0v4UljbMjiyxMUQiOK9KymVavQ2Y14",
		"ubuntu",
	}, lines)
}

func TestHostAuthorizedPrincipalsRejectsMultipleDomainsInOneFile(t *testing.T) {
	path := writeDomain(t, "domain", vectorDomain+vectorDomain)
	cmd := HostAuthorizedPrincipalsCLI{DomainFile: path, Account: "ubuntu"}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "must contain exactly one line")
}

func TestHostAuthorizedPrincipalsRejectsLiteralAccountWithWhitespace(t *testing.T) {
	path := writeDomain(t, "domain", vectorDomain)
	cmd := HostAuthorizedPrincipalsCLI{
		DomainFile:        path,
		AcceptAccountName: true,
		Account:           "not\na-principal",
	}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "cannot be emitted")
}

func TestHostAuthorizedPrincipalsRejectsMalformedDomain(t *testing.T) {
	path := writeDomain(t, "domain", "not a domain\n")
	cmd := HostAuthorizedPrincipalsCLI{DomainFile: path, Account: "ubuntu"}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "parsing principal domain")
}

func writeDomain(t *testing.T, name, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(value), 0o600))
	return path
}
