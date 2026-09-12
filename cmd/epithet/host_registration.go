package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type hostRegistration struct {
	endpoint   string
	credential string
	token      string
	proposal   inventory.Proposal
}

func (c *HostEnrollCLI) prepareRegistration(ctx context.Context, result *hostEnrollment, env *sshdEnvironment, cfg tlsconfig.Config) (*hostRegistration, error) {
	endpoint, err := caclient.InventoryURL(&caclient.RootResponse{FinalURL: result.CAFinalURL, Links: result.AdvertisedLinkFields}, cfg)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		if c.Token != "" || c.TokenFile != "" || c.ProposalFile != "" || c.Yes {
			return nil, fmt.Errorf("CA does not advertise managed inventory enrollment")
		}
		return nil, nil
	}
	if c.Token != "" && c.TokenFile != "" {
		return nil, fmt.Errorf("use either --token or --token-file")
	}
	token := c.Token
	if c.TokenFile != "" {
		data, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(data))
		if token == "" {
			return nil, fmt.Errorf("token file is empty")
		}
	}
	settings, err := c.resolveSSHDSettings(env)
	if err != nil {
		return nil, err
	}
	proposal := inventory.Proposal{Names: guessHostNames(ctx), Accounts: guessLoginAccounts(), Labels: map[string]string{}, PrincipalMode: inventory.PrincipalMode(settings.principalMode), Domain: string(result.Domain)}
	if len(c.Names) > 0 {
		proposal.Names = c.Names
	}
	if c.ProposalFile != "" {
		data, err := os.ReadFile(c.ProposalFile)
		if err != nil {
			return nil, err
		}
		proposal, err = inventory.ParseProposal(data)
		if err != nil {
			return nil, err
		}
	}
	validateLocal := func(p inventory.Proposal) error {
		if p.Domain != string(result.Domain) || string(p.PrincipalMode) != settings.principalMode {
			return fmt.Errorf("domain and principal-mode must match this host's local enrollment settings; use --principal-mode to select the mode")
		}
		return nil
	}
	if c.Yes {
		if c.ProposalFile == "" {
			return nil, fmt.Errorf("--yes requires --proposal-file with an explicitly prepared host proposal")
		}
	} else {
		proposal, err = editProposal(proposal, bufio.NewReader(os.Stdin), "submit", validateLocal)
		if err != nil {
			return nil, err
		}
	}
	if err = proposal.Validate(); err != nil {
		return nil, err
	}
	if err = validateLocal(proposal); err != nil {
		return nil, err
	}
	credential, err := ensureEnrollmentCredential(filepath.Join(filepath.Dir(result.DomainFile), "enrollment.key"))
	if err != nil {
		return nil, err
	}
	return &hostRegistration{endpoint, credential, token, proposal}, nil
}
func (r *hostRegistration) submit(ctx context.Context, result *hostEnrollment, cfg tlsconfig.Config, logger *slog.Logger) error {
	client, err := tlsconfig.NewHTTPClient(cfg)
	if err != nil {
		return err
	}
	response, _, err := caclient.DoInventory(ctx, client, r.endpoint, "", inventoryapi.ControlRequest{Action: "enroll", Host: &r.proposal, Credential: r.credential, Token: r.token})
	if err != nil {
		return fmt.Errorf("local sshd is configured, but registration did not complete; rerun enrollment to retry: %w", err)
	}
	if response.Host == nil {
		return fmt.Errorf("inventory returned no host record")
	}
	result.RecordID = response.Host.ID
	result.Status = response.Host.Status
	if logger != nil {
		logger.Info("host registration submitted", "id", result.RecordID, "status", result.Status)
	}
	return nil
}
func ensureEnrollmentCredential(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		value := strings.TrimSpace(string(data))
		if len(value) != 64 {
			return "", fmt.Errorf("invalid enrollment credential in %s", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if info.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("enrollment credential %s must be private (mode 0600)", path)
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	secret, err := inventory.RandomSecret()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".enrollment-key-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return "", err
	}
	if _, err = f.WriteString(secret + "\n"); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = os.Link(f.Name(), path); errors.Is(err, os.ErrExist) {
		return ensureEnrollmentCredential(path)
	} else if err != nil {
		return "", err
	}
	if err = syncEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return "", err
	}
	return secret, nil
}
func guessHostNames(ctx context.Context) []string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return []string{}
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	names := []string{name}
	// A bounded local resolver query can add the canonical FQDN. It is still a
	// proposal for the operator, never evidence of ownership.
	lookup, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if canonical, err := net.DefaultResolver.LookupCNAME(lookup, name); err == nil {
		canonical = strings.ToLower(strings.TrimSuffix(canonical, "."))
		if canonical != "" && !slices.Contains(names, canonical) {
			names = append(names, canonical)
		}
	}
	return names
}
func guessLoginAccounts() []string {
	accounts := []string{}
	add := func(name, shell string) {
		base := filepath.Base(shell)
		if name != "" && shell != "" && base != "false" && base != "nologin" && base != "sync" && base != "shutdown" && base != "halt" && !slices.Contains(accounts, name) {
			accounts = append(accounts, name)
		}
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if data, err := exec.CommandContext(ctx, "dscl", ".", "-list", "/Users", "UserShell").Output(); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				f := strings.Fields(line)
				if len(f) == 2 {
					add(f[0], f[1])
				}
			}
		}
	}
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(line, ":")
			if len(f) == 7 {
				add(f[0], f[6])
			}
		}
	}
	slices.Sort(accounts)
	return accounts
}
