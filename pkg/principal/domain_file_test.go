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
			got, err := defaultDomainPath(goos, func(string) string { return "" })
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestDefaultPathWindowsUsesProgramData(t *testing.T) {
	got, err := defaultDomainPath("windows", func(name string) string {
		require.Equal(t, "ProgramData", name)
		return `C:\ProgramData`
	})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(`C:\ProgramData`, "domain"), got)
}

func TestDefaultPathRejectsUnknownOS(t *testing.T) {
	_, err := defaultDomainPath("plan9", func(string) string { return "" })
	require.ErrorContains(t, err, "use an explicit path")
}

func TestDefaultPathMatchesCurrentOS(t *testing.T) {
	if runtime.GOOS == "plan9" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("current OS deliberately has no host-enrollment default")
	}
	_, err := DefaultDomainPath()
	require.NoError(t, err)
}

func TestEnsureFileCreatesAndThenReadsSameDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain")

	createdDomain, created, err := EnsureDomainFile(path)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, createdDomain.Validate())
	require.True(t, createdDomain.IsGeneratedHost())

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	readDomain, created, err := EnsureDomainFile(path)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, createdDomain, readDomain)
}

func TestEnsureFilePreservesNamedDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain")
	require.NoError(t, os.WriteFile(path, []byte("ai-worker-pool-1\n"), 0o644))

	domain, created, err := EnsureDomainFile(path)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, Domain("ai-worker-pool-1"), domain)
}

func TestEnsureFileRejectsMalformedExistingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain")
	require.NoError(t, os.WriteFile(path, []byte("broken domain\n"), 0o644))

	_, created, err := EnsureDomainFile(path)
	require.ErrorContains(t, err, "parsing principal domain")
	require.False(t, created)

	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, "broken domain\n", string(data), "malformed state must not be replaced")
}

func TestConcurrentEnsureFileReturnsOneDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain")
	const count = 16

	type result struct {
		domain  Domain
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
			domain, created, err := EnsureDomainFile(path)
			results <- result{domain: domain, created: created, err: err}
		}()
	}
	ready.Wait()
	close(start)

	var want Domain
	createdCount := 0
	for range count {
		result := <-results
		require.NoError(t, result.err)
		if want == "" {
			want = result.domain
		}
		require.Equal(t, want, result.domain)
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
			path := filepath.Join(t.TempDir(), "domain")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
			domain, err := ReadDomainFile(path)
			require.NoError(t, err)
			require.Equal(t, Domain("ai-worker-pool-1"), domain)
		})
	}
}

func TestReadFileRejectsAdditionalLinesAndWhitespace(t *testing.T) {
	for name, contents := range map[string]string{
		"two newlines":   "floop\n\n",
		"two domains":    "floop\nother\n",
		"leading space":  " floop\n",
		"trailing space": "floop \n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "domain")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
			_, err := ReadDomainFile(path)
			require.Error(t, err)
		})
	}
}

func TestEnsureFileRequiresExistingParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "domain")
	_, created, err := EnsureDomainFile(path)
	require.ErrorContains(t, err, "creating temporary principal domain")
	require.False(t, created)
}
