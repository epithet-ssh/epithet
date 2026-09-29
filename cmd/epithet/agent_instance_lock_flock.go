//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockProfileFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
