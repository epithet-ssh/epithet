package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/epithet-ssh/epithet/pkg/principal"
	"golang.org/x/crypto/ssh"
)

// HostCLI groups commands intended to run on or administer target hosts.
type HostCLI struct {
	AuthorizedPrincipals HostAuthorizedPrincipalsCLI `cmd:"authorized-principals" help:"Print the principals authorized for a local account"`
}

// HostAuthorizedPrincipalsCLI implements the offline
// AuthorizedPrincipalsCommand hook for sshd.
type HostAuthorizedPrincipalsCLI struct {
	HostKeys          []string `name:"host-key" help:"Designated host identity public-key file (repeatable during rotation)" required:""`
	AcceptAccountName bool     `name:"accept-account-name" help:"Also accept the literal account name during a bounded migration"`
	Account           string   `arg:"" name:"account" help:"Target account name supplied by sshd as %u" required:""`
}

func (c *HostAuthorizedPrincipalsCLI) Run() error {
	return c.writeAuthorizedPrincipals(os.Stdout)
}

func (c *HostAuthorizedPrincipalsCLI) writeAuthorizedPrincipals(dst io.Writer) error {
	if len(c.HostKeys) == 0 {
		return fmt.Errorf("at least one host public key is required")
	}
	if c.Account == "" {
		return fmt.Errorf("account name is empty")
	}
	if c.AcceptAccountName {
		if err := validateLiteralPrincipal(c.Account); err != nil {
			return err
		}
	}

	seen := make(map[string]struct{}, len(c.HostKeys))
	names := make([]string, 0, len(c.HostKeys)+1)
	for _, rawPath := range c.HostKeys {
		path, err := expandPath(rawPath)
		if err != nil {
			return fmt.Errorf("expanding host public-key path %q: %w", rawPath, err)
		}
		key, err := readHostPublicKey(path)
		if err != nil {
			return err
		}
		name, err := principal.DeriveV1(key, c.Account)
		if err != nil {
			return fmt.Errorf("deriving principal from %s: %w", path, err)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}

	if c.AcceptAccountName {
		names = append(names, c.Account)
	}
	for _, name := range names {
		if _, err := fmt.Fprintln(dst, name); err != nil {
			return fmt.Errorf("writing authorized principal: %w", err)
		}
	}
	return nil
}

func readHostPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading host public key %s: %w", path, err)
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing host public key %s: %w", path, err)
	}
	if len(options) != 0 {
		return nil, fmt.Errorf("host public key %s contains authorized_keys options", path)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("host public key %s contains more than one key", path)
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return nil, fmt.Errorf("host public key %s is an SSH certificate, not a public key", path)
	}
	return key, nil
}

func validateLiteralPrincipal(account string) error {
	for _, b := range []byte(account) {
		if b <= ' ' || b == 0x7f {
			return fmt.Errorf("account name cannot be emitted as an authorized principal")
		}
	}
	return nil
}
