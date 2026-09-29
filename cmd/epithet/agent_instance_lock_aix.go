//go:build aix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockProfileFile(file *os.File) error {
	lock := unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: 0,
		Start:  0,
		Len:    0,
	}
	return unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
}
