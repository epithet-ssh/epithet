//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package inventory

import (
	"fmt"
	"os"
	"runtime"
)

func lockManagedFile(_ *os.File) error {
	return fmt.Errorf("inventory locking is not supported on %s", runtime.GOOS)
}
