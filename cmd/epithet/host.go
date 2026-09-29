package main

import (
	"fmt"
	"io"
	"os"

	"github.com/epithet-ssh/epithet/pkg/principal"
)

// HostCLI groups commands intended to run on or administer target hosts.
type HostCLI struct {
	Enroll               HostEnrollCLI               `cmd:"enroll" help:"Bootstrap this host from a CA URL (run as root)"`
	AuthorizedPrincipals HostAuthorizedPrincipalsCLI `cmd:"authorized-principals" help:"Print the principals authorized for a local account"`
}

// HostAuthorizedPrincipalsCLI implements the offline
// AuthorizedPrincipalsCommand hook for sshd.
type HostAuthorizedPrincipalsCLI struct {
	DomainFile string `name:"principal-domain-file" help:"Principal-domain file" required:""`
	Account    string `arg:"" name:"account" help:"Target account name supplied by sshd as %u" required:""`
}

func (c *HostAuthorizedPrincipalsCLI) Run() error {
	return c.writeAuthorizedPrincipals(os.Stdout)
}

func (c *HostAuthorizedPrincipalsCLI) writeAuthorizedPrincipals(dst io.Writer) error {
	if c.DomainFile == "" {
		return fmt.Errorf("principal-domain file is required")
	}
	if c.Account == "" {
		return fmt.Errorf("account name is empty")
	}

	path, err := expandPath(c.DomainFile)
	if err != nil {
		return fmt.Errorf("expanding principal-domain path %q: %w", c.DomainFile, err)
	}
	domain, err := readDomain(path)
	if err != nil {
		return err
	}
	name, err := principal.DeriveV1(domain, c.Account)
	if err != nil {
		return fmt.Errorf("deriving principal from %s: %w", path, err)
	}

	if _, err := fmt.Fprintln(dst, name); err != nil {
		return fmt.Errorf("writing authorized principal: %w", err)
	}
	return nil
}

func readDomain(path string) (principal.Domain, error) {
	return principal.ReadDomainFile(path)
}
