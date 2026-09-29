//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package main

import (
	"fmt"
	"os"
	"runtime"
)

func lockProfileFile(_ *os.File) error {
	return fmt.Errorf("profile locking is not supported on %s", runtime.GOOS)
}
