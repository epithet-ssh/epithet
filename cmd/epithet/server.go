package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"golang.org/x/crypto/ssh"
)

// ServerCLI defines the CLI flags for the combined server command.
// It supervises CA, control, directory, and inventory processes. Only the router
// owns the public listener; each service has its own private Unix socket.
type ServerCLI struct {
	Listen     string `help:"Public address to listen on" short:"l" default:":8080"`
	ControlKey string `help:"Path to configured control signing key" name:"control-key-file" default:"/etc/epithet/control.key"`
	CAKey      string `help:"Path to CA private key" name:"ca-key-file" default:"/etc/epithet/ca.key"`

	// Policy flags threaded through to the CA subprocess. The
	// subprocess re-runs Kong against the same --config, so these are
	// only needed when configuring via flags rather than a config file.
	PolicyFile      string            `help:"Path to the writ policy file" name:"policy-file"`
	DirectoryStatic []string          `help:"Static directory file path or glob (repeatable)" name:"directory-static-file"`
	Extension       map[string]string `help:"Certificate extension for issued certs (name=value, repeatable)" name:"certificate-extension"`
}

func (c *ServerCLI) Run(logger *slog.Logger, _ tlsconfig.Config) error {
	caKeyPath := c.CAKey

	// Derive the trusted reader key for both fact services.
	privKeyBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("unable to load ca key from %s: %w", caKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to parse ca key: %w", err)
	}
	caPubkey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	logger.Info("derived ca public key", "path", caKeyPath)
	controlBytes, err := os.ReadFile(c.ControlKey)
	if err != nil {
		return fmt.Errorf("reading control key: %w", err)
	}
	controlSigner, err := ssh.ParsePrivateKey(controlBytes)
	if err != nil {
		return fmt.Errorf("parsing control key: %w", err)
	}
	controlPubkey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(controlSigner.PublicKey())))
	if controlPubkey == caPubkey {
		return fmt.Errorf("control must use a distinct signing key")
	}

	// The private socket directory is accessible only to this user.
	tmpDir, err := os.MkdirTemp("", "epithet-server-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	directorySock := filepath.Join(tmpDir, "directory.sock")
	controlSock := filepath.Join(tmpDir, "control.sock")

	// Set up signal-aware context for subprocess lifecycle.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Build global flags to pass through to subprocesses.
	globalArgs := buildGlobalArgs()

	inventorySock := filepath.Join(tmpDir, "inventory.sock")
	caSock := filepath.Join(tmpDir, "ca.sock")
	inventoryArgs := append(c.inventoryArgs(globalArgs, inventorySock, caPubkey), "--control-public-key", controlPubkey)
	directoryArgs := append(append([]string{}, globalArgs...), "directory", "--listen", "unix://"+directorySock, "--ca-public-key", caPubkey, "--control-public-key", controlPubkey)
	for _, path := range c.DirectoryStatic {
		directoryArgs = append(directoryArgs, "--directory-static-file", path)
	}
	caArgs := c.caArgs(globalArgs, caSock, directorySock, inventorySock, true)
	controlArgs := append(append([]string{}, globalArgs...), "control", "--listen", "unix://"+controlSock, "--control-key-file", c.ControlKey, "--directory", "unix://"+directorySock, "--directory-backend", "unix://"+directorySock, "--inventory-backend", "unix://"+inventorySock)
	auth, err := caChildOIDC(caArgs)
	if err != nil {
		return err
	}
	controlArgs = append(controlArgs, "--oidc-issuer", auth.Issuer, "--oidc-client-id", auth.ClientID)
	if auth.IdentityMode != "" {
		controlArgs = append(controlArgs, "--oidc-identity-mode", string(auth.IdentityMode))
	}
	if auth.UserIDClaim != "" {
		controlArgs = append(controlArgs, "--oidc-user-id-claim", auth.UserIDClaim)
	}
	type child struct {
		name   string
		args   []string
		socket string
	}
	children := []child{
		{"inventory", inventoryArgs, inventorySock},
		{"directory", directoryArgs, directorySock},
		{"control", controlArgs, controlSock},
		{"ca", caArgs, caSock},
		{"router", c.routerArgs(globalArgs, caSock, controlSock, true), ""},
	}
	var wg sync.WaitGroup
	exited := make(chan error, len(children))
	// Every started child is reaped, including startup failures and signals.
	defer func() { cancel(); wg.Wait() }()
	for _, child := range children {
		cmd := exec.CommandContext(ctx, os.Args[0], child.args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("starting %s: %w", child.name, err)
		}
		logger.Info("started subprocess", "service", child.name, "pid", cmd.Process.Pid)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cmd.Wait()
			exited <- fmt.Errorf("%s subprocess exited: %v", child.name, err)
		}()
		if child.socket != "" {
			ready := make(chan error, 1)
			go func() { ready <- waitForSocket(ctx, child.socket, 10*time.Second) }()
			select {
			case err := <-ready:
				if err != nil {
					return err
				}
			case err := <-exited:
				return err
			case <-ctx.Done():
				return nil
			}
		}
	}
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		return nil
	case err := <-exited:
		return err
	}
}

func (c *ServerCLI) caArgs(globalArgs []string, caSock, directorySock, inventorySock string, management bool) []string {
	publicURL := ""
	if management {
		publicURL = "inventory"
	}
	args := append(append([]string{}, globalArgs...), "ca", "--listen", "unix://"+caSock, "--directory", "unix://"+directorySock, "--inventory", "unix://"+inventorySock, "--ca-key-file", c.CAKey, "--control-public", publicURL)
	if c.PolicyFile != "" {
		args = append(args, "--policy-file", c.PolicyFile)
	}
	for name, value := range c.Extension {
		args = append(args, "--certificate-extension", name+"="+value)
	}
	return args
}

func (c *ServerCLI) routerArgs(globalArgs []string, caSock, inventorySock string, management bool) []string {
	endpoint := ""
	if management {
		endpoint = "unix://" + inventorySock
	}
	return append(append([]string{}, globalArgs...), "router", "--listen", c.Listen,
		"--ca-backend", "unix://"+caSock, "--control-backend", endpoint)
}

func (c *ServerCLI) inventoryArgs(globalArgs []string, socket, key string) []string {
	args := append(append([]string{}, globalArgs...), "inventory", "--listen", "unix://"+socket, "--ca-public-key", key)
	return args
}

// buildGlobalArgs constructs the global CLI flags to pass through to subprocesses.
func buildGlobalArgs() []string {
	var args []string
	if cli.Config != "" {
		args = append(args, "--config", string(cli.Config))
	}
	for i := 0; i < cli.Verbose; i++ {
		args = append(args, "-v")
	}
	if cli.Insecure {
		args = append(args, "--insecure")
	}
	if cli.TLSCACert != "" {
		args = append(args, "--tls-ca-cert-file", cli.TLSCACert)
	}
	if cli.LogFile != "" {
		args = append(args, "--log-file", cli.LogFile)
	}
	return args
}

// waitForSocket polls until a Unix domain socket accepts connections or the context is cancelled.
func waitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timed out waiting for socket %s", path)
		case <-ticker.C:
			conn, err := net.DialTimeout("unix", path, time.Second)
			if err == nil {
				conn.Close()
				return nil
			}
		}
	}
}

// Read the actual CA child configuration so the combined control process uses
// exactly the same identity mapping; separately managed services configure it explicitly.
func caChildOIDC(args []string) (ServiceOIDCConfig, error) {
	var root struct {
		Config    kong.ConfigFlag `name:"config"`
		Verbose   int             `short:"v" type:"counter"`
		LogFile   string          `name:"log-file"`
		Insecure  bool
		TLSCACert string `name:"tls-ca-cert-file"`
		CA        CACLI  `cmd:"ca"`
	}
	parser, err := kong.New(&root, kong.Configuration(loadCLIConfig, defaultConfigFiles()...))
	if err != nil {
		return ServiceOIDCConfig{}, err
	}
	if _, err = parser.Parse(args); err != nil {
		return ServiceOIDCConfig{}, err
	}
	return root.CA.OIDC, nil
}
