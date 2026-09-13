package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
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
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type hostRegistration struct {
	endpoint string
	token    string
	proposal inventory.Proposal
}

func (c *HostEnrollCLI) prepareRegistration(ctx context.Context, result *hostEnrollment, env *sshdEnvironment, cfg tlsconfig.Config) (*hostRegistration, error) {
	endpoint, err := caclient.InventoryURL(&caclient.RootResponse{FinalURL: result.CAFinalURL, Links: result.AdvertisedLinkFields}, cfg)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		if c.Token != "" || c.TokenFile != "" {
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
	proposal := inventory.Proposal{
		Names:         c.Names,
		Accounts:      guessLoginAccounts(),
		Labels:        map[string]string{},
		PrincipalMode: inventory.PrincipalMode(settings.principalMode),
		Domain:        string(result.Domain),
	}
	if len(proposal.Names) == 0 {
		proposal.Names = guessHostNames(ctx)
	}
	validateLocal := func(p inventory.Proposal) error {
		if p.Domain != string(result.Domain) || string(p.PrincipalMode) != settings.principalMode {
			return fmt.Errorf("domain and principal-mode must match this host's local enrollment settings; use --principal-mode to select the mode")
		}
		return nil
	}
	proposal, err = editProposal(proposal, bufio.NewReader(os.Stdin), "submit", validateLocal)
	if err != nil {
		return nil, err
	}
	return &hostRegistration{endpoint: endpoint, token: token, proposal: proposal}, nil
}

func (r *hostRegistration) submit(ctx context.Context, result *hostEnrollment, cfg tlsconfig.Config, logger *slog.Logger) error {
	client, err := inventoryclient.New(r.endpoint, cfg)
	if err != nil {
		return err
	}
	response, _, err := client.Control(ctx, "", inventoryapi.ControlRequest{
		Action: "enroll",
		Host:   &r.proposal,
		Token:  r.token,
	})
	if err != nil {
		return fmt.Errorf("local sshd is configured, but registration did not complete; check inventory before submitting another enrollment: %w", err)
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

// guessHostNames only reads local configuration; it never resolves DNS names.
func guessHostNames(ctx context.Context) []string {
	name, err := os.Hostname()
	if err != nil {
		return []string{}
	}
	return proposedHostNames(name, configuredSearchDomain(ctx))
}

func proposedHostNames(name, domain string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	domain = strings.ToLower(strings.Trim(domain, "."))
	if name == "" {
		return []string{}
	}
	if domain != "" && name != domain && !strings.HasSuffix(name, "."+domain) {
		name += "." + domain
	}
	return []string{name}
}

func configuredSearchDomain(ctx context.Context) string {
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		// scutil reads macOS resolver configuration; --dns does not do a lookup.
		if data, err := exec.CommandContext(ctx, "scutil", "--dns").Output(); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				key, value, ok := strings.Cut(line, ":")
				if ok && strings.TrimSpace(key) == "search domain[0]" {
					return strings.TrimSpace(value)
				}
			}
		}
	}
	data, _ := os.ReadFile("/etc/resolv.conf")
	return resolvSearchDomain(string(data))
}

func resolvSearchDomain(config string) string {
	domain := ""
	for _, line := range strings.Split(config, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, ";")
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "search" || fields[0] == "domain") {
			domain = fields[1]
		}
	}
	return domain
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
