package principal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultDomainPath returns the native system-wide principal-domain path for this
// operating system. Callers may offer an explicit override for other layouts.
func DefaultDomainPath() (string, error) {
	return defaultDomainPath(runtime.GOOS, os.Getenv)
}

func defaultDomainPath(goos string, getenv func(string) string) (string, error) {
	var dir string
	switch goos {
	case "linux":
		dir = "/var/lib/epithet"
	case "dragonfly", "freebsd", "netbsd", "openbsd":
		dir = "/var/db/epithet"
	case "aix", "illumos", "solaris":
		dir = "/var/opt/epithet"
	case "darwin":
		dir = "/Library/Application Support/Epithet"
	case "windows":
		dir = getenv("ProgramData")
		if dir == "" {
			return "", fmt.Errorf("ProgramData is not set")
		}
	default:
		return "", fmt.Errorf("no default principal-domain path for %s; use an explicit path", goos)
	}
	return filepath.Join(dir, "domain"), nil
}

// ReadDomainFile reads one literal principal domain. A file may omit its final line
// ending or contain exactly one LF or CRLF; all other lines are rejected.
func ReadDomainFile(path string) (Domain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading principal domain %s: %w", path, err)
	}
	text := string(data)
	switch {
	case strings.HasSuffix(text, "\r\n"):
		text = strings.TrimSuffix(text, "\r\n")
	case strings.HasSuffix(text, "\n"):
		text = strings.TrimSuffix(text, "\n")
	}
	if strings.ContainsAny(text, "\r\n") {
		return "", fmt.Errorf("principal domain %s must contain exactly one line", path)
	}
	domain, err := ParseDomain(text)
	if err != nil {
		return "", fmt.Errorf("parsing principal domain %s: %w", path, err)
	}
	return domain, nil
}

// EnsureDomainFile installs the supplied domain, or reuses an existing file with
// that same value. It never replaces an existing directory entry or substitutes
// a different domain. Callers can therefore review a domain before publishing it.
// The parent directory must already exist with its final ownership and permissions.
func EnsureDomainFile(path string, domain Domain) (created bool, err error) {
	if path == "" {
		return false, fmt.Errorf("principal-domain path is empty")
	}
	if err := domain.Validate(); err != nil {
		return false, err
	}
	if matches, err := domainFileMatches(path, domain); err != nil || matches {
		return false, err
	}

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".epithet-domain-*")
	if err != nil {
		return false, fmt.Errorf("creating temporary principal domain in %s: %w", dir, err)
	}
	tempPath := f.Name()
	defer os.Remove(tempPath)
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("setting principal-domain permissions on %s: %w", tempPath, err)
	}
	if _, err := io.WriteString(f, domain.String()+"\n"); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("writing principal domain %s: %w", tempPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("syncing principal domain %s: %w", tempPath, err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("closing principal domain %s: %w", tempPath, err)
	}

	// A same-directory hard link publishes the complete file atomically and
	// fails rather than replacing an enrollment that won the race.
	if err := os.Link(tempPath, path); errors.Is(err, os.ErrExist) {
		matches, err := domainFileMatches(path, domain)
		if err == nil && !matches {
			err = fmt.Errorf("principal domain %s disappeared during installation", path)
		}
		return false, err
	} else if err != nil {
		return false, fmt.Errorf("publishing principal domain %s: %w", path, err)
	}
	if err := os.Remove(tempPath); err != nil {
		return true, fmt.Errorf("removing temporary principal domain %s: %w", tempPath, err)
	}
	if err := syncDirectory(dir); err != nil {
		return true, fmt.Errorf("syncing principal-domain directory %s: %w", dir, err)
	}
	return true, nil
}

func domainFileMatches(path string, expected Domain) (bool, error) {
	existing, err := ReadDomainFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if existing != expected {
		return false, fmt.Errorf("principal domain %s conflicts with the prepared domain; refusing to replace it", path)
	}
	return true, nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
