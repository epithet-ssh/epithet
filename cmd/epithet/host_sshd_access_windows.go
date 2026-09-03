//go:build windows

package main

import (
	"fmt"
	"os"
	"os/user"
)

func validateAuthorizedPrincipalsAccess(binary, hostIDPath, caKeyPath, commandUser string, destinationBound bool) error {
	if destinationBound {
		if _, err := user.Lookup(commandUser); err != nil {
			return fmt.Errorf("looking up AuthorizedPrincipalsCommandUser %q: %w", commandUser, err)
		}
	}
	paths := map[string]string{
		"host-ID file":       hostIDPath,
		"CA public-key file": caKeyPath,
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
