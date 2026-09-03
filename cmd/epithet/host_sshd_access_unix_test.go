//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequireRootControlledPathRejectsWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-id")
	require.NoError(t, os.WriteFile(path, []byte("identity\n"), 0o666))
	require.NoError(t, os.Chmod(path, 0o666))

	err := requireRootControlledPath(path)
	require.Error(t, err)
}
