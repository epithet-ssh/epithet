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
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type hostRegistration struct {
	endpoint string
	token    string
	proposal inventory.Proposal
}

func (c *HostEnrollCLI) prepareRegistration(ctx context.Context, result *hostEnrollment, settings *sshdSettings, cfg tlsconfig.Config) (*hostRegistration, error) {
	endpoint, err := caclient.InventoryURL(&caclient.RootResponse{FinalURL: result.CAFinalURL, Links: result.AdvertisedLinkFields}, cfg)
	if err != nil {
		return nil, err
	}

	if endpoint != "" {
		client, e := facts.NewAdminClient(endpoint, cfg)
		if e != nil {
			return nil, e
		}
		capabilities, e := client.Capabilities(ctx)
		if e != nil {
			return nil, e
		}
		if !slices.Contains(capabilities.Capabilities, "enroll") {
			endpoint = ""
		}
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
	proposal := inventory.Proposal{
		Names:         c.Names,
		Accounts:      guessLoginAccounts(),
		Labels:        map[string]string{},
		PrincipalMode: inventory.PrincipalMode(settings.principalMode),
		Realm:         string(result.Realm),
	}
	if len(proposal.Names) == 0 {
		proposal.Names = guessHostNames(ctx)
	}
	validateLocal := func(p inventory.Proposal) error {
		if string(p.PrincipalMode) != settings.principalMode {
			return fmt.Errorf("principal-mode must match this host's local enrollment settings; use --principal-mode to select the mode")
		}
		if _, err := principal.ParseRealm(p.Realm); err != nil {
			return err
		}
		installed, err := readRealmIfPresent(result.RealmFile)
		if err != nil {
			return err
		}
		if installed != "" && p.Realm != string(installed) {
			return fmt.Errorf("realm conflicts with the installed realm in %s", result.RealmFile)
		}
		return nil
	}
	proposal, err = editProposal(proposal, bufio.NewReader(os.Stdin), validateLocal)
	if err != nil {
		return nil, err
	}
	// The reviewed proposal chooses the identity installed locally and submitted
	// to inventory. No realm has been written before review completes.
	result.Realm = principal.Realm(proposal.Realm)
	return &hostRegistration{endpoint: endpoint, token: token, proposal: proposal}, nil
}

func (r *hostRegistration) submit(ctx context.Context, result *hostEnrollment, cfg tlsconfig.Config, logger *slog.Logger) error {
	client, err := facts.NewAdminClient(r.endpoint, cfg)
	if err != nil {
		return err
	}
	proposal := r.proposal.ControlProposal()
	response, _, err := client.Control(ctx, "", facts.ControlRequest{
		Action: "enroll",
		Host:   &proposal,
		Token:  r.token,
	})
	if err != nil {
		return fmt.Errorf("local sshd is configured, but registration did not complete: %w", err)
	}
	if response.Host == nil {
		return fmt.Errorf("local sshd is configured, but inventory returned no host record")
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
	return proposedHostNames(name, configuredSearchRealm(ctx))
}

func proposedHostNames(name, realm string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	realm = strings.ToLower(strings.Trim(realm, "."))
	if name == "" {
		return []string{}
	}
	if realm != "" && name != realm && !strings.HasSuffix(name, "."+realm) {
		name += "." + realm
	}
	return []string{name}
}

func configuredSearchRealm(ctx context.Context) string {
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		// scutil reads macOS resolver configuration; --dns does not do a lookup.
		if data, err := exec.CommandContext(ctx, "scutil", "--dns").Output(); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				key, value, ok := strings.Cut(line, ":")
				if ok && strings.TrimSpace(key) == "search realm[0]" {
					return strings.TrimSpace(value)
				}
			}
		}
	}
	data, _ := os.ReadFile("/etc/resolv.conf")
	return resolvSearchRealm(string(data))
}

func resolvSearchRealm(config string) string {
	realm := ""
	for _, line := range strings.Split(config, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, ";")
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "search" || fields[0] == "realm") {
			realm = fields[1]
		}
	}
	return realm
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
