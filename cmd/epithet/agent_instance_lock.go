package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// acquireProfileLock takes an exclusive, non-blocking flock on
// <runDir>/agent.lock so at most one agent process ever owns a given
// profile's rundir: two agents sharing a rundir would race on
// removing/recreating the live broker socket (startBrokerListener does an
// os.Remove before listening), silently orphaning whichever one loses.
// Returning early with a clear error is much better than that.
//
// The returned file's fd is intentionally never closed or unlocked here:
// holding it open for the life of the process is exactly what pins the
// lock, and the OS releases the flock automatically when the process exits
// (normally or via signal), which is precisely when the lock should be
// released. Callers must keep the returned *os.File reachable for as long
// as the lock needs to be held (see runtime.KeepAlive at the call site) —
// otherwise the os.File finalizer could close the fd, and the lock with it,
// while the process is still running.
func acquireProfileLock(runDir, name string) (*os.File, error) {
	lockPath := filepath.Join(runDir, "agent.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}
	if err := lockProfileFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("profile %q is already running (use --agent-name to run a second profile)", name)
	}
	return f, nil
}
