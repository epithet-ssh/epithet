package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"golang.org/x/crypto/ssh"
)

// HostEnrollCLI bootstraps the durable local state needed to enroll a host.
type HostEnrollCLI struct {
	Token     string   `name:"token" help:"Single-use enrollment token"`
	TokenFile string   `name:"token-file" help:"File containing a single-use enrollment token"`
	Names     []string `name:"name" help:"Proposed DNS name (repeatable; overrides detection)"`

	CAURL                           string   `name:"ca-url" help:"CA bootstrap URL" required:""`
	PrincipalDomain                 string   `name:"principal-domain" help:"Proposed principal domain (default: reuse the local domain file's value or generate one)"`
	DomainFile                      string   `name:"domain-file" help:"Principal-domain file (default: native system state directory)"`
	CAPubkeyFile                    string   `name:"ca-pubkey-file" help:"CA public-key file (default: epithet-ca.pub beside the domain file)"`
	PrincipalMode                   string   `name:"principal-mode" help:"Principal mode to accept: account-name or epithet-principal-v1 (default: epithet-principal-v1; account-name on Windows)"`
	SSHDConfigFile                  string   `name:"sshd-config-file" help:"Main sshd configuration file (default: platform native)"`
	SSHDFragmentFile                string   `name:"sshd-fragment-file" help:"Epithet-managed sshd fragment (default: platform native)"`
	SSHDBinary                      string   `name:"sshd-binary" help:"sshd executable used to validate configuration"`
	EpithetBinary                   string   `name:"epithet-binary" help:"Epithet executable written into AuthorizedPrincipalsCommand"`
	AuthorizedPrincipalsCommandUser string   `name:"authorized-principals-command-user" help:"Unprivileged account used for AuthorizedPrincipalsCommand" default:"nobody"`
	ReloadCommand                   string   `name:"reload-command" help:"Service reload executable (default: platform native)"`
	ReloadArgs                      []string `name:"reload-arg" help:"Argument for --reload-command (repeatable)"`

	sshdEnv *sshdEnvironment
}

type hostEnrollment struct {
	RecordID             string
	Status               string
	Domain               principal.Domain
	DomainFile           string
	DomainCreated        bool
	CAPublicKey          sshcert.RawPublicKey
	CAPubkeyFile         string
	CAPublicKeyCreated   bool
	CAFinalURL           string
	AdvertisedLinkFields []string
}

func (c *HostEnrollCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	result, err := c.enroll(context.Background(), logger, tlsCfg)
	if errors.Is(err, errCanceled) {
		return nil
	}
	if err != nil {
		return err
	}
	if result.RecordID != "" {
		_, err = fmt.Fprintf(os.Stdout, "%s\t%s\n", result.RecordID, result.Status)
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, result.Domain)
	return err
}

func (c *HostEnrollCLI) enroll(ctx context.Context, logger *slog.Logger, tlsCfg tlsconfig.Config) (*hostEnrollment, error) {
	env := c.sshdEnv
	if env == nil {
		env = newSystemSSHDEnvironment()
	}
	prepared, err := c.prepareEnrollment(ctx, logger, tlsCfg, env)
	if err != nil {
		return nil, err
	}
	result := prepared.state
	registration, err := c.prepareRegistration(ctx, result, prepared.settings, tlsCfg)
	if err != nil {
		return nil, err
	}
	if err := result.install(logger); err != nil {
		return nil, err
	}
	if err := configureSSHD(ctx, result, prepared.settings, env); err != nil {
		return nil, err
	}
	if registration != nil {
		if err := registration.submit(ctx, result, tlsCfg, logger); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// preparedHostEnrollment holds the local identity and resolved settings for this
// attempt. Preparation reads existing state and generates any new domain in
// memory; installation happens only after proposal review succeeds.
type preparedHostEnrollment struct {
	state    *hostEnrollment
	settings *sshdSettings
}

func (c *HostEnrollCLI) prepareEnrollment(ctx context.Context, logger *slog.Logger, tlsCfg tlsconfig.Config, env *sshdEnvironment) (*preparedHostEnrollment, error) {
	// Recover existing choices on a local copy, preserving the caller's explicit
	// inputs so each invocation resolves them afresh.
	options := *c
	if err := options.adoptExistingSSHDEnrollment(env); err != nil {
		return nil, err
	}
	settings, err := options.resolveSSHDSettings(env)
	if err != nil {
		return nil, err
	}
	state, err := options.prepareState(ctx, logger, tlsCfg)
	if err != nil {
		return nil, err
	}
	return &preparedHostEnrollment{state: state, settings: settings}, nil
}

// prepareState fetches trust and chooses a domain without writing local state.
func (c *HostEnrollCLI) prepareState(ctx context.Context, logger *slog.Logger, tlsCfg tlsconfig.Config) (*hostEnrollment, error) {
	endpoint, err := caclient.ParseCAURL(c.CAURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ca-url: %w", err)
	}
	if err := tlsCfg.ValidateURL(endpoint.URL); err != nil {
		return nil, err
	}

	domainPath, caKeyPath, err := c.paths()
	if err != nil {
		return nil, err
	}
	if filepath.Clean(domainPath) == filepath.Clean(caKeyPath) {
		return nil, fmt.Errorf("principal-domain file and CA public-key file must be different paths")
	}

	client, err := caclient.New([]caclient.CAEndpoint{endpoint},
		caclient.WithLogger(logger),
		caclient.WithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("creating CA client: %w", err)
	}
	root, err := client.GetRoot(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching CA public key from %s: %w", endpoint.URL, err)
	}

	domain, err := readDomainIfPresent(domainPath)
	if err != nil {
		return nil, err
	}
	if c.PrincipalDomain != "" {
		chosen, err := principal.ParseDomain(c.PrincipalDomain)
		if err != nil {
			return nil, fmt.Errorf("invalid principal-domain: %w", err)
		}
		if domain != "" && domain != chosen {
			return nil, fmt.Errorf("principal-domain conflicts with the installed domain in %s", domainPath)
		}
		domain = chosen
	}
	if _, err := publicKeyFileMatches(caKeyPath, root.PublicKey); err != nil {
		return nil, err
	}
	if domain == "" {
		domain, err = principal.GenerateHostDomain()
		if err != nil {
			return nil, err
		}
	}
	return &hostEnrollment{
		Domain:               domain,
		DomainFile:           domainPath,
		CAPublicKey:          root.PublicKey,
		CAPubkeyFile:         caKeyPath,
		CAFinalURL:           root.FinalURL,
		AdvertisedLinkFields: append([]string(nil), root.Links...),
	}, nil
}

// install publishes the reviewed identity and trust. Existing matching files are
// reused; conflicting state is never replaced. Later sshd or registration errors
// leave these files in place for the next invocation.
func (e *hostEnrollment) install(logger *slog.Logger) error {
	// Recheck both files after review before writing either one.
	domain, err := readDomainIfPresent(e.DomainFile)
	if err != nil {
		return err
	}
	if domain != "" && domain != e.Domain {
		return fmt.Errorf("principal domain %s changed since preparation", e.DomainFile)
	}
	if _, err := publicKeyFileMatches(e.CAPubkeyFile, e.CAPublicKey); err != nil {
		return err
	}
	for _, dir := range uniqueDirectories(e.DomainFile, e.CAPubkeyFile) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating enrollment directory %s: %w", dir, err)
		}
	}
	e.CAPublicKeyCreated, err = ensurePublicKeyFile(e.CAPubkeyFile, e.CAPublicKey)
	if err != nil {
		return err
	}
	e.DomainCreated, err = principal.EnsureDomainFile(e.DomainFile, e.Domain)
	if err != nil {
		return err
	}
	if logger != nil {
		logger.Info("host enrollment state ready",
			"domain", e.Domain,
			"domain_file", e.DomainFile,
			"domain_created", e.DomainCreated,
			"ca_public_key_file", e.CAPubkeyFile,
			"ca_public_key_created", e.CAPublicKeyCreated)
	}
	return nil
}

func (c *HostEnrollCLI) paths() (string, string, error) {
	domainPath := c.DomainFile
	if domainPath == "" {
		var err error
		domainPath, err = principal.DefaultDomainPath()
		if err != nil {
			return "", "", err
		}
	}
	domainPath, err := expandPath(domainPath)
	if err != nil {
		return "", "", fmt.Errorf("expanding principal-domain path %q: %w", c.DomainFile, err)
	}

	caKeyPath := c.CAPubkeyFile
	if caKeyPath == "" {
		caKeyPath = filepath.Join(filepath.Dir(domainPath), "epithet-ca.pub")
	}
	caKeyPath, err = expandPath(caKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("expanding CA public-key path %q: %w", c.CAPubkeyFile, err)
	}
	return domainPath, caKeyPath, nil
}

func readDomainIfPresent(path string) (principal.Domain, error) {
	domain, err := principal.ReadDomainFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return domain, err
}

func publicKeyFileMatches(path string, expected sshcert.RawPublicKey) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading CA public key %s: %w", path, err)
	}
	existing, err := sshcert.ParsePublicKey(sshcert.RawPublicKey(data))
	if err != nil {
		return false, fmt.Errorf("parsing CA public key %s: %w", path, err)
	}
	wanted, err := sshcert.ParsePublicKey(expected)
	if err != nil {
		return false, fmt.Errorf("parsing fetched CA public key: %w", err)
	}
	if !bytes.Equal(existing.Marshal(), wanted.Marshal()) {
		return false, fmt.Errorf("CA public key %s conflicts with the key returned by the CA; refusing to replace it", path)
	}
	return true, nil
}

func ensurePublicKeyFile(path string, key sshcert.RawPublicKey) (bool, error) {
	if matches, err := publicKeyFileMatches(path, key); err != nil || matches {
		return false, err
	}

	parsed, err := sshcert.ParsePublicKey(key)
	if err != nil {
		return false, fmt.Errorf("parsing fetched CA public key: %w", err)
	}
	canonical := ssh.MarshalAuthorizedKey(parsed)
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".epithet-ca-key-*")
	if err != nil {
		return false, fmt.Errorf("creating temporary CA public key in %s: %w", dir, err)
	}
	tempPath := f.Name()
	defer os.Remove(tempPath)
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("setting CA public-key permissions on %s: %w", tempPath, err)
	}
	if _, err := f.Write(canonical); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("writing CA public key %s: %w", tempPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("syncing CA public key %s: %w", tempPath, err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("closing CA public key %s: %w", tempPath, err)
	}

	if err := os.Link(tempPath, path); errors.Is(err, os.ErrExist) {
		matches, checkErr := publicKeyFileMatches(path, key)
		if checkErr != nil {
			return false, checkErr
		}
		if !matches {
			return false, fmt.Errorf("CA public key %s appeared during enrollment but could not be validated", path)
		}
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("publishing CA public key %s: %w", path, err)
	}
	if err := os.Remove(tempPath); err != nil {
		return true, fmt.Errorf("removing temporary CA public key %s: %w", tempPath, err)
	}
	if err := syncDirectory(dir); err != nil {
		return true, fmt.Errorf("syncing CA public-key directory %s: %w", dir, err)
	}
	return true, nil
}

func uniqueDirectories(paths ...string) []string {
	seen := make(map[string]bool, len(paths))
	dirs := make([]string, 0, len(paths))
	for _, path := range paths {
		dir := filepath.Dir(path)
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
