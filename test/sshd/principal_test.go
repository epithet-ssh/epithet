package sshd_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
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

	hostAPrincipal, err := principal.DeriveV1(hostA.HostID(), hostA.User)
	require.NoError(t, err)
	hostBPrincipal, err := principal.DeriveV1(hostB.HostID(), hostB.User)
	require.NoError(t, err)
	require.NotEqual(t, hostAPrincipal, hostBPrincipal)

	userPublicKey, userPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	certificate, err := testCA.SignPublicKey(userPublicKey, &wire.CertParams{
		Identity:   "destination-binding-test",
		Names:      []string{hostAPrincipal},
		Expiration: time.Minute,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	a := agent.New(testLogger(t), "")
	go func() {
		if err := a.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("agent.Serve: %v", err)
		}
	}()
	require.NoError(t, a.WaitReady())
	t.Cleanup(a.Close)
	require.NoError(t, a.UseCredential(agent.Credential{
		PrivateKey:  userPrivateKey,
		Certificate: certificate,
	}))

	out, err := hostA.Ssh(a)
	require.NoError(t, err, "intended host should accept its derived principal; ssh output:\n%s\nsshd output:\n%s", out, hostA.Output.String())
	require.Contains(t, out, "hello from sshd")

	out, err = hostB.Ssh(a)
	require.Error(t, err, "another host must reject the same certificate")
	require.Contains(t, out, "Permission denied")
}

func newPrincipalTestCA(t *testing.T) (*ca.CA, sshcert.RawPublicKey) {
	t.Helper()
	publicKey, privateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	testCA, err := ca.New(privateKey, "http://unused.invalid")
	require.NoError(t, err)
	return testCA, publicKey
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
