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

// DefaultRealmPath returns the native system-wide principal-realm path for this
// operating system. Callers may offer an explicit override for other layouts.
func DefaultRealmPath() (string, error) {
	return defaultRealmPath(runtime.GOOS, os.Getenv)
}

func defaultRealmPath(goos string, getenv func(string) string) (string, error) {
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
		return "", fmt.Errorf("no default principal-realm path for %s; use an explicit path", goos)
	}
	// The identity filename is independent of the public terminology. Retain
	// its path so existing enrollment keeps the same authorization boundary.
	return filepath.Join(dir, "domain"), nil
}

// ReadRealmFile reads one literal principal realm. A file may omit its final line
// ending or contain exactly one LF or CRLF; all other lines are rejected.
func ReadRealmFile(path string) (Realm, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading principal realm %s: %w", path, err)
	}
	text := string(data)
	switch {
	case strings.HasSuffix(text, "\r\n"):
		text = strings.TrimSuffix(text, "\r\n")
	case strings.HasSuffix(text, "\n"):
		text = strings.TrimSuffix(text, "\n")
	}
	if strings.ContainsAny(text, "\r\n") {
		return "", fmt.Errorf("principal realm %s must contain exactly one line", path)
	}
	realm, err := ParseRealm(text)
	if err != nil {
		return "", fmt.Errorf("parsing principal realm %s: %w", path, err)
	}
	return realm, nil
}

// EnsureRealmFile installs the supplied realm, or reuses an existing file with
// that same value. It never replaces an existing directory entry or substitutes
// a different realm. Callers can therefore review a realm before publishing it.
// The parent directory must already exist with its final ownership and permissions.
func EnsureRealmFile(path string, realm Realm) (created bool, err error) {
	if path == "" {
		return false, fmt.Errorf("principal-realm path is empty")
	}
	if err := realm.Validate(); err != nil {
		return false, err
	}
	if matches, err := realmFileMatches(path, realm); err != nil || matches {
		return false, err
	}

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".epithet-realm-*")
	if err != nil {
		return false, fmt.Errorf("creating temporary principal realm in %s: %w", dir, err)
	}
	tempPath := f.Name()
	defer os.Remove(tempPath)
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("setting principal-realm permissions on %s: %w", tempPath, err)
	}
	if _, err := io.WriteString(f, realm.String()+"\n"); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("writing principal realm %s: %w", tempPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("syncing principal realm %s: %w", tempPath, err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("closing principal realm %s: %w", tempPath, err)
	}

	// A same-directory hard link publishes the complete file atomically and
	// fails rather than replacing an enrollment that won the race.
	if err := os.Link(tempPath, path); errors.Is(err, os.ErrExist) {
		matches, err := realmFileMatches(path, realm)
		if err == nil && !matches {
			err = fmt.Errorf("principal realm %s disappeared during installation", path)
		}
		return false, err
	} else if err != nil {
		return false, fmt.Errorf("publishing principal realm %s: %w", path, err)
	}
	if err := os.Remove(tempPath); err != nil {
		return true, fmt.Errorf("removing temporary principal realm %s: %w", tempPath, err)
	}
	if err := syncDirectory(dir); err != nil {
		return true, fmt.Errorf("syncing principal-realm directory %s: %w", dir, err)
	}
	return true, nil
}

func realmFileMatches(path string, expected Realm) (bool, error) {
	existing, err := ReadRealmFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if existing != expected {
		return false, fmt.Errorf("principal realm %s conflicts with the prepared realm; refusing to replace it", path)
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
