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
	"github.com/epithet-ssh/epithet/pkg/hostid"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"golang.org/x/crypto/ssh"
)

// HostEnrollCLI bootstraps the durable local state needed to enroll a host.
type HostEnrollCLI struct {
	CAURL                           string   `name:"ca-url" help:"CA bootstrap URL" required:""`
	HostIDFile                      string   `name:"host-id-file" help:"Host-ID file (default: native system state directory)"`
	CAPubkeyFile                    string   `name:"ca-pubkey-file" help:"CA public-key file (default: epithet-ca.pub beside the host-ID file)"`
	PrincipalMode                   string   `name:"principal-mode" help:"Principal mode to accept (default: epithet-principal-v1; account-name on Windows)" enum:"account-name,epithet-principal-v1"`
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
	HostID               hostid.ID
	HostIDFile           string
	HostIDCreated        bool
	CAPublicKey          sshcert.RawPublicKey
	CAPubkeyFile         string
	CAPublicKeyCreated   bool
	CAFinalURL           string
	AdvertisedLinkFields []string
}

func (c *HostEnrollCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	result, err := c.enroll(context.Background(), logger, tlsCfg)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, result.HostID)
	return err
}

func (c *HostEnrollCLI) enroll(ctx context.Context, logger *slog.Logger, tlsCfg tlsconfig.Config) (*hostEnrollment, error) {
	env := c.sshdEnv
	if env == nil {
		env = newSystemSSHDEnvironment()
	}
	if err := c.adoptExistingSSHDEnrollment(env); err != nil {
		return nil, err
	}
	result, err := c.enrollState(ctx, logger, tlsCfg)
	if err != nil {
		return nil, err
	}
	if err := c.configureSSHD(ctx, result, env); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *HostEnrollCLI) enrollState(ctx context.Context, logger *slog.Logger, tlsCfg tlsconfig.Config) (*hostEnrollment, error) {
	endpoint, err := caclient.ParseCAURL(c.CAURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ca-url: %w", err)
	}
	if err := tlsCfg.ValidateURL(endpoint.URL); err != nil {
		return nil, err
	}

	hostIDPath, caKeyPath, err := c.paths()
	if err != nil {
		return nil, err
	}
	if filepath.Clean(hostIDPath) == filepath.Clean(caKeyPath) {
		return nil, fmt.Errorf("host-ID file and CA public-key file must be different paths")
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

	// Check all existing state before creating anything. In particular, a
	// conflicting CA key must not accidentally mint an identity for this host.
	if _, err := readHostIDIfPresent(hostIDPath); err != nil {
		return nil, err
	}
	if _, err := publicKeyFileMatches(caKeyPath, root.PublicKey); err != nil {
		return nil, err
	}

	for _, dir := range uniqueDirectories(hostIDPath, caKeyPath) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("creating enrollment directory %s: %w", dir, err)
		}
	}

	caCreated, err := ensurePublicKeyFile(caKeyPath, root.PublicKey)
	if err != nil {
		return nil, err
	}
	hostID, hostCreated, err := hostid.EnsureFile(hostIDPath)
	if err != nil {
		return nil, err
	}

	if logger != nil {
		logger.Info("host enrollment state ready",
			"host_id_file", hostIDPath,
			"host_id_created", hostCreated,
			"ca_public_key_file", caKeyPath,
			"ca_public_key_created", caCreated)
	}
	return &hostEnrollment{
		HostID:               hostID,
		HostIDFile:           hostIDPath,
		HostIDCreated:        hostCreated,
		CAPublicKey:          root.PublicKey,
		CAPubkeyFile:         caKeyPath,
		CAPublicKeyCreated:   caCreated,
		CAFinalURL:           root.FinalURL,
		AdvertisedLinkFields: append([]string(nil), root.Links...),
	}, nil
}

func (c *HostEnrollCLI) paths() (string, string, error) {
	hostIDPath := c.HostIDFile
	if hostIDPath == "" {
		var err error
		hostIDPath, err = hostid.DefaultPath()
		if err != nil {
			return "", "", err
		}
	}
	hostIDPath, err := expandPath(hostIDPath)
	if err != nil {
		return "", "", fmt.Errorf("expanding host-ID path %q: %w", c.HostIDFile, err)
	}

	caKeyPath := c.CAPubkeyFile
	if caKeyPath == "" {
		caKeyPath = filepath.Join(filepath.Dir(hostIDPath), "epithet-ca.pub")
	}
	caKeyPath, err = expandPath(caKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("expanding CA public-key path %q: %w", c.CAPubkeyFile, err)
	}
	return hostIDPath, caKeyPath, nil
}

func readHostIDIfPresent(path string) (hostid.ID, error) {
	id, err := hostid.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return id, err
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
	if err := syncEnrollmentDirectory(dir); err != nil {
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

func syncEnrollmentDirectory(path string) error {
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
