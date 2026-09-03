package hostid

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultPath(t *testing.T) {
	tests := map[string]string{
		"linux":     "/var/lib/epithet/host-id",
		"freebsd":   "/var/db/epithet/host-id",
		"openbsd":   "/var/db/epithet/host-id",
		"netbsd":    "/var/db/epithet/host-id",
		"dragonfly": "/var/db/epithet/host-id",
		"solaris":   "/var/opt/epithet/host-id",
		"illumos":   "/var/opt/epithet/host-id",
		"aix":       "/var/opt/epithet/host-id",
		"darwin":    "/Library/Application Support/Epithet/host-id",
	}
	for goos, want := range tests {
		t.Run(goos, func(t *testing.T) {
			got, err := defaultPath(goos, func(string) string { return "" })
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestDefaultPathWindowsUsesProgramData(t *testing.T) {
	got, err := defaultPath("windows", func(name string) string {
		require.Equal(t, "ProgramData", name)
		return `C:\ProgramData`
	})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(`C:\ProgramData`, "host-id"), got)
}

func TestDefaultPathRejectsUnknownOS(t *testing.T) {
	_, err := defaultPath("plan9", func(string) string { return "" })
	require.ErrorContains(t, err, "use an explicit path")
}

func TestDefaultPathMatchesCurrentOS(t *testing.T) {
	if runtime.GOOS == "plan9" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("current OS deliberately has no host-enrollment default")
	}
	_, err := DefaultPath()
	require.NoError(t, err)
}

func TestEnsureFileCreatesAndThenReadsSameID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-id")

	createdID, created, err := EnsureFile(path)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, createdID.Validate())

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	readID, created, err := EnsureFile(path)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, createdID, readID)
}

func TestEnsureFileRejectsMalformedExistingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-id")
	require.NoError(t, os.WriteFile(path, []byte("broken\n"), 0o644))

	_, created, err := EnsureFile(path)
	require.ErrorContains(t, err, "parsing host ID")
	require.False(t, created)

	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, "broken\n", string(data), "malformed state must not be replaced")
}

func TestConcurrentEnsureFileReturnsOneID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-id")
	const count = 16

	type result struct {
		id      ID
		created bool
		err     error
	}
	results := make(chan result, count)
	var ready sync.WaitGroup
	ready.Add(count)
	start := make(chan struct{})
	for range count {
		go func() {
			ready.Done()
			<-start
			id, created, err := EnsureFile(path)
			results <- result{id: id, created: created, err: err}
		}()
	}
	ready.Wait()
	close(start)

	var want ID
	createdCount := 0
	for range count {
		result := <-results
		require.NoError(t, result.err)
		if want == "" {
			want = result.id
		}
		require.Equal(t, want, result.id)
		if result.created {
			createdCount++
		}
	}
	require.Equal(t, 1, createdCount)
}

func TestReadFileRejectsAdditionalLinesAndWhitespace(t *testing.T) {
	valid, err := Generate()
	require.NoError(t, err)

	for name, contents := range map[string]string{
		"two newlines":   valid.String() + "\n\n",
		"two IDs":        valid.String() + "\n" + valid.String() + "\n",
		"leading space":  " " + valid.String() + "\n",
		"trailing space": valid.String() + " \n",
		"CRLF":           valid.String() + "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "host-id")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
			_, err := ReadFile(path)
			require.Error(t, err)
		})
	}
}

func TestEnsureFileRequiresExistingParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "host-id")
	_, created, err := EnsureFile(path)
	require.ErrorContains(t, err, "creating temporary host ID")
	require.False(t, created)
}
