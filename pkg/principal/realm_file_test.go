package principal

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
		"linux":     "/var/lib/epithet/domain",
		"freebsd":   "/var/db/epithet/domain",
		"openbsd":   "/var/db/epithet/domain",
		"netbsd":    "/var/db/epithet/domain",
		"dragonfly": "/var/db/epithet/domain",
		"solaris":   "/var/opt/epithet/domain",
		"illumos":   "/var/opt/epithet/domain",
		"aix":       "/var/opt/epithet/domain",
		"darwin":    "/Library/Application Support/Epithet/domain",
	}
	for goos, want := range tests {
		t.Run(goos, func(t *testing.T) {
			got, err := defaultRealmPath(goos, func(string) string { return "" })
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestDefaultPathWindowsUsesProgramData(t *testing.T) {
	got, err := defaultRealmPath("windows", func(name string) string {
		require.Equal(t, "ProgramData", name)
		return `C:\ProgramData`
	})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(`C:\ProgramData`, "domain"), got)
}

func TestDefaultPathRejectsUnknownOS(t *testing.T) {
	_, err := defaultRealmPath("plan9", func(string) string { return "" })
	require.ErrorContains(t, err, "use an explicit path")
}

func TestDefaultPathMatchesCurrentOS(t *testing.T) {
	if runtime.GOOS == "plan9" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("current OS deliberately has no host-enrollment default")
	}
	_, err := DefaultRealmPath()
	require.NoError(t, err)
}

func TestEnsureFileCreatesAndThenReadsSameRealm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "realm")

	createdRealm, err := GenerateHostRealm()
	require.NoError(t, err)
	created, err := EnsureRealmFile(path, createdRealm)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, createdRealm.Validate())
	require.True(t, createdRealm.IsGeneratedHost())

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	created, err = EnsureRealmFile(path, createdRealm)
	require.NoError(t, err)
	readRealm, err := ReadRealmFile(path)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, createdRealm, readRealm)
}

func TestEnsureFilePreservesNamedRealm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "realm")
	require.NoError(t, os.WriteFile(path, []byte("ai-worker-pool-1\n"), 0o644))

	created, err := EnsureRealmFile(path, "ai-worker-pool-1")
	realm, readErr := ReadRealmFile(path)
	require.NoError(t, readErr)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, Realm("ai-worker-pool-1"), realm)
}

func TestEnsureFileRejectsMalformedExistingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "realm")
	require.NoError(t, os.WriteFile(path, []byte("broken realm\n"), 0o644))

	created, err := EnsureRealmFile(path, "ai-worker-pool-1")
	require.ErrorContains(t, err, "parsing principal realm")
	require.False(t, created)

	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, "broken realm\n", string(data), "malformed state must not be replaced")
}

func TestConcurrentEnsureFileInstallsReviewedRealm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "realm")
	const count = 16

	type result struct {
		realm   Realm
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
			created, err := EnsureRealmFile(path, "reviewed-realm")
			realm, readErr := ReadRealmFile(path)
			if err == nil {
				err = readErr
			}
			results <- result{realm: realm, created: created, err: err}
		}()
	}
	ready.Wait()
	close(start)

	var want Realm
	createdCount := 0
	for range count {
		result := <-results
		require.NoError(t, result.err)
		if want == "" {
			want = result.realm
		}
		require.Equal(t, want, result.realm)
		if result.created {
			createdCount++
		}
	}
	require.Equal(t, 1, createdCount)
}

func TestReadFileLineEndings(t *testing.T) {
	for name, contents := range map[string]string{
		"none": "ai-worker-pool-1",
		"LF":   "ai-worker-pool-1\n",
		"CRLF": "ai-worker-pool-1\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "realm")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
			realm, err := ReadRealmFile(path)
			require.NoError(t, err)
			require.Equal(t, Realm("ai-worker-pool-1"), realm)
		})
	}
}

func TestReadFileRejectsAdditionalLinesAndWhitespace(t *testing.T) {
	for name, contents := range map[string]string{
		"two newlines":   "floop\n\n",
		"two realms":     "floop\nother\n",
		"leading space":  " floop\n",
		"trailing space": "floop \n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "realm")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
			_, err := ReadRealmFile(path)
			require.Error(t, err)
		})
	}
}

func TestEnsureFileRequiresExistingParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "realm")
	created, err := EnsureRealmFile(path, "ai-worker-pool-1")
	require.ErrorContains(t, err, "creating temporary principal realm")
	require.False(t, created)
}

func TestEnsureFileRejectsDifferentReviewedRealm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "realm")
	created, err := EnsureRealmFile(path, "first-realm")
	require.NoError(t, err)
	require.True(t, created)
	created, err = EnsureRealmFile(path, "second-realm")
	require.ErrorContains(t, err, "conflicts with the prepared realm")
	require.False(t, created)
	realm, err := ReadRealmFile(path)
	require.NoError(t, err)
	require.Equal(t, Realm("first-realm"), realm)
}
