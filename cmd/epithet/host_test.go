package main

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestHostAuthorizedPrincipalsRejectsMultipleDomainsInOneFile(t *testing.T) {
	path := writeDomain(t, "domain", vectorDomain+vectorDomain)
	cmd := HostAuthorizedPrincipalsCLI{DomainFile: path, Account: "ubuntu"}

	err := cmd.writeAuthorizedPrincipals(&bytes.Buffer{})
	require.ErrorContains(t, err, "must contain exactly one line")
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
