//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package main

import (
	"fmt"
	"os"
)

func validateAuthorizedPrincipalsAccess(binary, domainPath, caKeyPath, _ string, destinationBound bool) error {
	paths := map[string]string{
		"principal-domain file": domainPath,
		"CA public-key file":    caKeyPath,
	}
	if destinationBound {
		paths["AuthorizedPrincipalsCommand"] = binary
	}
	for description, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("statting %s %s: %w", description, path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s %s is not a regular file", description, path)
		}
	}
	return nil
}
