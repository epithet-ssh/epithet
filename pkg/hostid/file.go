package hostid

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultPath returns the native system-wide host-ID path for this operating
// system. Callers may offer an explicit override for other layouts.
func DefaultPath() (string, error) {
	return defaultPath(runtime.GOOS, os.Getenv)
}

func defaultPath(goos string, getenv func(string) string) (string, error) {
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
		return "", fmt.Errorf("no default host-ID path for %s; use an explicit path", goos)
	}
	return filepath.Join(dir, "host-id"), nil
}

// ReadFile reads one canonical host ID. A file may omit its final newline or
// contain exactly one; all other surrounding whitespace and additional lines
// are rejected.
func ReadFile(path string) (ID, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading host ID %s: %w", path, err)
	}
	text := string(data)
	if strings.HasSuffix(text, "\n") {
		text = strings.TrimSuffix(text, "\n")
	}
	if strings.ContainsAny(text, "\r\n") {
		return "", fmt.Errorf("host ID %s must contain exactly one line", path)
	}
	id, err := Parse(text)
	if err != nil {
		return "", fmt.Errorf("parsing host ID %s: %w", path, err)
	}
	return id, nil
}

// EnsureFile returns the existing canonical host ID at path or creates a new
// one. It never replaces an existing directory entry. The parent directory
// must already exist with its final ownership and permissions.
func EnsureFile(path string) (id ID, created bool, err error) {
	if path == "" {
		return "", false, fmt.Errorf("host-ID path is empty")
	}
	id, err = ReadFile(path)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}

	id, err = Generate()
	if err != nil {
		return "", false, err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".epithet-host-id-*")
	if err != nil {
		return "", false, fmt.Errorf("creating temporary host ID in %s: %w", dir, err)
	}
	tempPath := f.Name()
	defer os.Remove(tempPath)
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return "", false, fmt.Errorf("setting host ID permissions on %s: %w", tempPath, err)
	}
	if _, err := io.WriteString(f, id.String()+"\n"); err != nil {
		_ = f.Close()
		return "", false, fmt.Errorf("writing host ID %s: %w", tempPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", false, fmt.Errorf("syncing host ID %s: %w", tempPath, err)
	}
	if err := f.Close(); err != nil {
		return "", false, fmt.Errorf("closing host ID %s: %w", tempPath, err)
	}

	// A same-directory hard link publishes the complete file atomically and
	// fails rather than replacing an enrollment that won the race.
	if err := os.Link(tempPath, path); errors.Is(err, os.ErrExist) {
		id, err = ReadFile(path)
		return id, false, err
	} else if err != nil {
		return "", false, fmt.Errorf("publishing host ID %s: %w", path, err)
	}
	if err := os.Remove(tempPath); err != nil {
		return id, true, fmt.Errorf("removing temporary host ID %s: %w", tempPath, err)
	}
	if err := syncDirectory(dir); err != nil {
		return id, true, fmt.Errorf("syncing host-ID directory %s: %w", dir, err)
	}
	return id, true, nil
}

func syncDirectory(path string) error {
	// Windows does not expose directory fsync through os.File.Sync. The hard
	// link still provides atomic publication there.
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
