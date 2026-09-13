package sshd_test

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestDestinationBoundPrincipalIsRejectedByAnotherHost(t *testing.T) {
	testCA, caPublicKey := newPrincipalTestCA(t)
	epithetBin := buildEpithet(t)

	hostA, err := sshd.StartWithEpithetAuthorizedPrincipals(caPublicKey, epithetBin, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = hostA.Close() })
	hostB, err := sshd.StartWithEpithetAuthorizedPrincipals(caPublicKey, epithetBin, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = hostB.Close() })

	hostAPrincipal, err := principal.DeriveV1(hostA.Domain(), hostA.User)
	require.NoError(t, err)
	hostBPrincipal, err := principal.DeriveV1(hostB.Domain(), hostB.User)
	require.NoError(t, err)
	require.NotEqual(t, hostAPrincipal, hostBPrincipal)

	userPublicKey, userPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	certificate := signPrincipalTestCertificate(t, testCA, userPublicKey, "destination-binding-test", hostAPrincipal)

	a, err := agent.Start(testLogger(t), "", agent.Credential{
		PrivateKey:  userPrivateKey,
		Certificate: certificate,
	})
	require.NoError(t, err)
	t.Cleanup(a.Close)

	out, err := hostA.Ssh(a)
	require.NoError(t, err, "intended host should accept its derived principal; ssh output:\n%s\nsshd output:\n%s", out, hostA.Output.String())
	require.Contains(t, out, "hello from sshd")

	out, err = hostB.Ssh(a)
	require.Error(t, err, "another host must reject the same certificate")
	require.Contains(t, out, "Permission denied")
}

func TestPrincipalDomainIsAcceptedAcrossFleet(t *testing.T) {
	testCA, caPublicKey := newPrincipalTestCA(t)
	epithetBin := buildEpithet(t)
	domain := principal.Domain("ai-worker-pool-1")

	hostA, err := sshd.StartWithEpithetAuthorizedPrincipalsInDomain(caPublicKey, epithetBin, false, domain)
	require.NoError(t, err)
	t.Cleanup(func() { _ = hostA.Close() })
	hostB, err := sshd.StartWithEpithetAuthorizedPrincipalsInDomain(caPublicKey, epithetBin, false, domain)
	require.NoError(t, err)
	t.Cleanup(func() { _ = hostB.Close() })

	fleetPrincipal, err := principal.DeriveV1(domain, hostA.User)
	require.NoError(t, err)
	userPublicKey, userPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	certificate := signPrincipalTestCertificate(t, testCA, userPublicKey, "principal-domain-test", fleetPrincipal)

	a, err := agent.Start(testLogger(t), "", agent.Credential{
		PrivateKey:  userPrivateKey,
		Certificate: certificate,
	})
	require.NoError(t, err)
	t.Cleanup(a.Close)

	out, err := hostA.Ssh(a)
	require.NoError(t, err, "first fleet host should accept its domain principal; ssh output:\n%s\nsshd output:\n%s", out, hostA.Output.String())
	out, err = hostB.Ssh(a)
	require.NoError(t, err, "second fleet host should accept the shared domain principal; ssh output:\n%s\nsshd output:\n%s", out, hostB.Output.String())
}

func newPrincipalTestCA(t *testing.T) (ssh.Signer, sshcert.RawPublicKey) {
	t.Helper()
	publicKey, privateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	testCA, err := ssh.ParsePrivateKey([]byte(privateKey))
	require.NoError(t, err)
	return testCA, publicKey
}

// These tests exercise sshd principal matching with a locally signed fixture.
func signPrincipalTestCertificate(t *testing.T, signer ssh.Signer, publicKey sshcert.RawPublicKey, identity, name string) sshcert.RawCertificate {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	require.NoError(t, err)
	now := time.Now()
	cert := &ssh.Certificate{
		Key: key, KeyId: identity, CertType: ssh.UserCert,
		ValidPrincipals: []string{name},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(time.Minute).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, signer))
	return sshcert.RawCertificate(ssh.MarshalAuthorizedKey(cert))
}

func buildEpithet(t *testing.T) string {
	t.Helper()
	// AuthorizedPrincipalsCommand rejects executables beneath world-writable
	// path components such as /tmp, even when the executable itself is safe.
	// t.TempDir uses the platform's user-private test directory on macOS.
	path := filepath.Join(t.TempDir(), "epithet")
	out, err := exec.Command("go", "build", "-o", path, "../../cmd/epithet").CombinedOutput()
	require.NoError(t, err, "build epithet: %s", out)
	require.NoError(t, os.Chmod(path, 0o755), "remove group-writable mode rejected by sshd")
	return path
}
