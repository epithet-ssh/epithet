package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// SystemStateDir is the native location for Epithet service state. It does not
// create directories or depend on a user's agent profile. Explicit storage paths
// bypass this default, including on operating systems without a known convention.
func SystemStateDir() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return "/var/lib/epithet", nil
	case "dragonfly", "freebsd", "netbsd", "openbsd":
		return "/var/db/epithet", nil
	case "aix", "illumos", "solaris":
		return "/var/opt/epithet", nil
	case "darwin":
		return "/Library/Application Support/Epithet", nil
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			return "", fmt.Errorf("ProgramData is not set; configure an explicit storage path")
		}
		return filepath.Join(base, "Epithet"), nil
	default:
		return "", fmt.Errorf("no default system state directory for %s; configure an explicit storage path", runtime.GOOS)
	}
}
