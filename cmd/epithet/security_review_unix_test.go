//go:build securityreview && (darwin || linux || freebsd)

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// This probe isolates the ownership gate and rendered path; it does not enroll
// a host or alter sshd. File content is irrelevant to this ownership check, so
// an existing root-controlled system file stands in for an enrolled public key.
func TestReviewEnrollmentAcceptsUserReplaceableSymlink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("probe requires an unprivileged user")
	}
	rootFile, err := filepath.EvalSymlinks("/bin/sh")
	require.NoError(t, err)
	require.NoError(t, requireRootControlledPath(rootFile))
	dir := t.TempDir()
	link := filepath.Join(dir, "ca.pub")
	require.NoError(t, os.Symlink(rootFile, link))
	// Both key and domain ownership gates currently check only resolved paths.
	require.NoError(t, validateAuthorizedPrincipalsAccess("", link, link, "", false))
	fragment, err := renderSSHDFragment(&sshdSettings{
		principalMode: accountNamePrincipalMode,
	}, link, link, "linux")
	require.NoError(t, err)
	require.Contains(t, string(fragment), "TrustedUserCAKeys \""+link+"\"")
	// The unprivileged owner can change what the emitted sshd path resolves to.
	controlled := filepath.Join(dir, "replacement.pub")
	require.NoError(t, os.WriteFile(controlled, []byte("review replacement"), 0600))
	require.NoError(t, os.Remove(link))
	require.NoError(t, os.Symlink(controlled, link))
	content, err := os.ReadFile(link)
	require.NoError(t, err)
	require.Equal(t, "review replacement", string(content))
	t.Log("ownership gate passed, but emitted TrustedUserCAKeys path remained user-replaceable")
}
