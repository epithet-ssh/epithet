package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// systemStateDir is the native location for Epithet service state. It does not
// create directories or depend on a user's agent profile. Explicit storage paths
// bypass this default, including on operating systems without a known convention.
func systemStateDir(goos string, getenv func(string) string) (string, error) {
	switch goos {
	case "linux":
		return "/var/lib/epithet", nil
	case "dragonfly", "freebsd", "netbsd", "openbsd":
		return "/var/db/epithet", nil
	case "aix", "illumos", "solaris":
		return "/var/opt/epithet", nil
	case "darwin":
		return "/Library/Application Support/Epithet", nil
	case "windows":
		base := getenv("ProgramData")
		if base == "" {
			return "", fmt.Errorf("ProgramData is not set; configure an explicit storage path")
		}
		return filepath.Join(base, "Epithet"), nil
	default:
		return "", fmt.Errorf("no default system state directory for %s; configure an explicit storage path", goos)
	}
}

// Resolve paths only for enabled stores; static mode never opens managed state.
func serviceStatePath(root string, elements ...string) (string, error) {
	var err error
	if root == "" {
		root, err = systemStateDir(runtime.GOOS, os.Getenv)
	} else {
		root, err = expandPath(root)
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{root}, elements...)...), nil
}

// defaultRealmPath shares service-state placement while preserving the realm's
// established filename. File validation and installation belong to principal.
func defaultRealmPath(goos string, getenv func(string) string) (string, error) {
	// Windows enrollment predates the Epithet service-state subdirectory.
	// Keep its existing path; moving it would change the host's realm lookup.
	if goos == "windows" {
		dir := getenv("ProgramData")
		if dir == "" {
			return "", fmt.Errorf("ProgramData is not set")
		}
		return filepath.Join(dir, "domain"), nil
	}
	dir, err := systemStateDir(goos, getenv)
	if err != nil {
		return "", fmt.Errorf("no default principal-realm path: %w; use an explicit path", err)
	}
	return filepath.Join(dir, "domain"), nil
}
