//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

func validateAuthorizedPrincipalsAccess(binary, domainPath, caKeyPath, commandUser string, destinationBound bool) error {
	resolvedDomain, err := filepath.EvalSymlinks(domainPath)
	if err != nil {
		return fmt.Errorf("resolving principal-domain file %s: %w", domainPath, err)
	}
	if err := requireRootControlledPath(resolvedDomain); err != nil {
		return fmt.Errorf("principal-domain file: %w", err)
	}
	resolvedCAKey, err := filepath.EvalSymlinks(caKeyPath)
	if err != nil {
		return fmt.Errorf("resolving CA public-key file %s: %w", caKeyPath, err)
	}
	if err := requireRootControlledPath(resolvedCAKey); err != nil {
		return fmt.Errorf("CA public-key file: %w", err)
	}
	if !destinationBound {
		return nil
	}

	account, err := user.Lookup(commandUser)
	if err != nil {
		return fmt.Errorf("looking up AuthorizedPrincipalsCommandUser %q: %w", commandUser, err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("parsing uid for %q: %w", commandUser, err)
	}
	groups := make(map[uint32]bool)
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("parsing primary gid for %q: %w", commandUser, err)
	}
	groups[uint32(gid)] = true
	groupIDs, err := account.GroupIds()
	if err == nil {
		for _, groupID := range groupIDs {
			parsed, err := strconv.ParseUint(groupID, 10, 32)
			if err != nil {
				return fmt.Errorf("parsing group id %q for %q: %w", groupID, commandUser, err)
			}
			groups[uint32(parsed)] = true
		}
	}

	resolvedBinary, err := filepath.EvalSymlinks(binary)
	if err != nil {
		return fmt.Errorf("resolving AuthorizedPrincipalsCommand %s: %w", binary, err)
	}
	binaryInfo, err := os.Stat(resolvedBinary)
	if err != nil {
		return fmt.Errorf("statting AuthorizedPrincipalsCommand %s: %w", resolvedBinary, err)
	}
	if !binaryInfo.Mode().IsRegular() {
		return fmt.Errorf("AuthorizedPrincipalsCommand %s is not a regular file", resolvedBinary)
	}
	stat, ok := binaryInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect ownership of AuthorizedPrincipalsCommand %s", resolvedBinary)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("AuthorizedPrincipalsCommand %s must be owned by root", resolvedBinary)
	}
	if binaryInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("AuthorizedPrincipalsCommand %s must not be writable by group or others", resolvedBinary)
	}
	if err := requireRootControlledPath(resolvedBinary); err != nil {
		return fmt.Errorf("AuthorizedPrincipalsCommand: %w", err)
	}
	if err := requirePathAccess(resolvedBinary, uint32(uid), groups, 0o1, commandUser); err != nil {
		return fmt.Errorf("AuthorizedPrincipalsCommand: %w", err)
	}

	if err := requirePathAccess(resolvedDomain, uint32(uid), groups, 0o4, commandUser); err != nil {
		return fmt.Errorf("principal-domain file: %w", err)
	}
	return nil
}

func requireRootControlledPath(path string) error {
	current := path
	for {
		info, err := os.Stat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot inspect ownership of %s", current)
		}
		if stat.Uid != 0 {
			return fmt.Errorf("%s must be owned by root", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must not be writable by group or others", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func requirePathAccess(path string, uid uint32, groups map[uint32]bool, permission os.FileMode, username string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !modeAllows(info, uid, groups, permission) {
		return fmt.Errorf("%s is not accessible to %q", path, username)
	}

	dir := filepath.Dir(path)
	for {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || !modeAllows(info, uid, groups, 0o1) {
			return fmt.Errorf("directory %s is not searchable by %q", dir, username)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func modeAllows(info os.FileInfo, uid uint32, groups map[uint32]bool, permission os.FileMode) bool {
	if uid == 0 {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	mode := info.Mode().Perm()
	var granted os.FileMode
	switch {
	case stat.Uid == uid:
		granted = (mode >> 6) & 0o7
	case groups[stat.Gid]:
		granted = (mode >> 3) & 0o7
	default:
		granted = mode & 0o7
	}
	return granted&permission == permission
}
