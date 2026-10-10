package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"golang.org/x/oauth2"
)

// profileNamePattern restricts profile names to characters that are safe to
// embed unescaped in a filesystem path and in an ssh_config Tag/Match token.
var profileNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validateProfileName rejects profile names that would be unsafe to embed in
// a rundir path or an ssh_config Tag token.
func validateProfileName(name string) error {
	if !profileNamePattern.MatchString(name) {
		return fmt.Errorf("invalid profile name %q: must match %s", name, profileNamePattern.String())
	}
	return nil
}

// resolveAgentBrokerSocket locates the broker controlled by agent subcommands
// such as inspect and kill. An explicit socket overrides profile discovery.
func resolveAgentBrokerSocket(parent *AgentCLI, override string) (string, error) {
	if override != "" {
		brokerSock, err := expandPath(override)
		if err != nil {
			return "", fmt.Errorf("failed to expand broker socket path: %w", err)
		}
		return brokerSock, nil
	}
	if err := validateProfileName(parent.Name); err != nil {
		return "", err
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".epithet", "run", parent.Name, "broker.sock"), nil
}

// AgentCLI is the parent command for agent-related subcommands.
// Shared flags are defined here and inherited by subcommands.
type AgentCLI struct {
	Name        string        `help:"Profile name; names the rundir and the ssh Tag (epithet-<name>, or just epithet for the default profile)" default:"default" name:"agent-name"`
	CaURL       []string      `placeholder:"URL" help:"CA URL (repeatable, format: priority=N:https://url or https://url)" name:"ca" short:"c"`
	CaTimeout   time.Duration `help:"Per-request timeout for CA requests" name:"ca-timeout" default:"15s"`
	CaCooldown  time.Duration `help:"Circuit breaker cooldown for failed CAs" name:"ca-cooldown" default:"10m"`
	LoginMethod string        `help:"Interactive login method" name:"login-method" enum:"auto,browser,device" default:"auto"`

	Login    AgentLoginCLI    `cmd:"login" help:"Authenticate the running agent without requesting a certificate"`
	Logout   AgentLogoutCLI   `cmd:"logout" help:"Clear this profile's certificate agents and login state"`
	Identity AgentIdentityCLI `cmd:"identity" aliases:"id,ident" help:"Authenticate the running agent and print its OIDC identity"`
	Start    AgentStartCLI    `cmd:"" default:"withargs" help:"Start the epithet agent"`
	Inspect  AgentInspectCLI  `cmd:"inspect" aliases:"i, in,ins,list,ls" help:"Inspect broker state (certificates, agents)"`
	Kill     AgentKillCLI     `cmd:"kill" help:"Kill one agent and discard its certificate"`
}

// AgentStartCLI is the default subcommand that starts the agent/broker.
type AgentStartCLI struct {
	Command []string `arg:"" optional:"" passthrough:"" name:"command" help:"Command to run while the agent is available"`
}

func (s *AgentStartCLI) Run(parent *AgentCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	// Validate required fields for start
	if len(parent.CaURL) == 0 {
		return fmt.Errorf("--ca is required (at least one)")
	}

	if err := validateProfileName(parent.Name); err != nil {
		return err
	}

	// Parse CA URLs into endpoints
	caEndpoints, err := caclient.ParseCAURLs(parent.CaURL)
	if err != nil {
		return fmt.Errorf("invalid CA URL: %w", err)
	}

	logger.Debug("agent start command received", "ca_urls", parent.CaURL, "ca_timeout", parent.CaTimeout, "ca_cooldown", parent.CaCooldown)

	// Validate all CA URLs require TLS (unless --insecure)
	for _, ep := range caEndpoints {
		if err := tlsCfg.ValidateURL(ep.URL); err != nil {
			return fmt.Errorf("CA URL %q: %w", ep.URL, err)
		}
	}

	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// The rundir is named after the profile, not derived from CA URLs: it is
	// stable across restarts so a fixed ssh_config exec line and IdentityAgent
	// path keep working without regenerating ~/.ssh/config. Ownership of a
	// named dir is unambiguous (one profile, one agent process at a time), so
	// there is nothing to garbage-collect: startup truncates and rewrites the
	// config, and startBrokerListener removes and recreates the socket.
	runDir := filepath.Join(homeDir, ".epithet", "run", parent.Name)

	// Create run directory
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return fmt.Errorf("failed to create run directory: %w", err)
	}

	// Guard against a second agent process silently stealing this profile's
	// socket: without this, a concurrent `epithet agent` with the same
	// --agent-name (e.g. two shells both using the "default" profile) would
	// os.Remove the live socket out from under the first process, orphaning
	// it with no error. lockFile is deliberately kept alive for the rest of
	// Run() via the runtime.KeepAlive below (see acquireProfileLock's docs).
	lockFile, err := acquireProfileLock(runDir, parent.Name)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(lockFile)

	// Define paths within the run directory
	brokerSock := filepath.Join(runDir, "broker.sock")
	agentDir := filepath.Join(runDir, "agent")

	// Create agent directory
	if err := os.MkdirAll(agentDir, 0700); err != nil {
		return fmt.Errorf("failed to create agent directory: %w", err)
	}

	// Create CA client
	caClientOpts := []caclient.Option{
		caclient.WithLogger(logger),
		caclient.WithTimeout(parent.CaTimeout),
		caclient.WithCooldown(parent.CaCooldown),
		caclient.WithTLSConfig(tlsCfg),
	}
	caClient, err := caclient.New(caEndpoints, caClientOpts...)
	if err != nil {
		return fmt.Errorf("failed to create CA client: %w", err)
	}

	// Discover the auth config from the CA's anonymous bootstrap endpoint.
	logger.Debug("discovering auth config from CA")
	discovery, err := caClient.GetDiscovery(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get discovery config from CA: %w", err)
	}
	if discovery == nil || discovery.Auth == nil {
		return fmt.Errorf("CA discovery did not include authentication configuration")
	}
	logger.Info("discovered auth config from CA", "issuer", discovery.Auth.Issuer)

	loginMethod, inferredDevice := resolveLoginMethod(parent.LoginMethod, os.Getenv)
	logger.Info("selected interactive login method", "method", loginMethodName(loginMethod), "configured", parent.LoginMethod)
	oidcCfg := oidc.LoginConfig{
		IssuerURL:    discovery.Auth.Issuer,
		ClientID:     discovery.Auth.ClientID,
		ClientSecret: discovery.Auth.ClientSecret,
		TLSConfig:    tlsCfg,
		LoginMethod:  loginMethod,
	}
	// Each login session owns its refresh state. Logout discards the entire
	// session; Auth serializes calls within that session.
	tokenFactory := func() broker.TokenFunc {
		var oauthState *oauth2.Token
		return func(ctx context.Context, out io.Writer, force bool) (string, error) {
			if force && oauthState != nil {
				// The broker calls us with force=true only after the CA rejected a
				// token, i.e. after 401'ing on the id_token derived from this exact
				// oauthState. Authenticate treats a time-valid access token as
				// reusable and would hand back that same rejected id_token, so we
				// backdate its expiry to force the refresh-token (or full re-auth)
				// path, which mints a genuinely new id_token.
				oauthState.Expiry = time.Now().Add(-time.Minute)
			}
			idToken, next, err := oidc.Authenticate(ctx, oidcCfg, oauthState, out)
			if err != nil {
				if inferredDevice && errors.Is(err, oidc.ErrDeviceAuthorizationUnsupported) {
					return "", fmt.Errorf("automatic device login is unavailable: %w; use --login-method browser to use a local callback", err)
				}
				return "", err
			}
			oauthState = next
			return idToken, nil
		}
	}

	// Bind inventory management to the endpoint advertised by the CA.
	inventoryClient, err := facts.NewAdminClient(discovery.InventoryURL, tlsCfg)
	if err != nil {
		return err
	}
	b, err := broker.New(*logger, brokerSock, tokenFactory, caClient, discovery.PublicCAURL, inventoryClient,
		makeAgentIdentityVerifier(*discovery.Auth, tlsCfg), agentDir)
	if err != nil {
		return fmt.Errorf("failed to create broker: %w", err)
	}

	// Set up context with cancellation on signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("received shutdown signal")
		cancel()
	}()

	// Generate SSH config file in the run directory
	sshConfigPath := filepath.Join(runDir, "ssh-config.conf")

	if err := parent.generateSSHConfig(sshConfigPath, agentDir, brokerSock, homeDir); err != nil {
		logger.Warn("failed to generate SSH config", "error", err, "path", sshConfigPath)
		// Don't fail startup, just warn
	} else {
		// Check if ~/.ssh/config has the Include directive
		includePattern := filepath.Join(homeDir, ".epithet", "run", "*", "ssh-config.conf")
		if err := checkSSHConfigInclude(homeDir, includePattern, parent.Name, logger); err != nil {

			logger.Warn(fmt.Sprintf("Add 'Include %s' to ~/.ssh/config", includePattern))
		}
		logger.Debug("generated SSH config", "path", sshConfigPath)
	}

	// Start broker, optionally scoped to a subprocess.
	logger.Info("starting broker", "socket", brokerSock)
	if len(s.Command) > 0 {
		err = runAgentCommand(ctx, cancel, b, s.Command)
	} else {
		err = b.Serve(ctx)
	}
	if err != nil && err != context.Canceled {
		var childErr childProcessError
		if errors.As(err, &childErr) {
			return childErr
		}
		return fmt.Errorf("broker serve error: %w", err)
	}

	logger.Info("broker shutdown complete")
	return nil
}

// resolveLoginMethod keeps environment detection at the command boundary and
// gives the authentication package only the concrete mechanism it must run.
func resolveLoginMethod(configured string, getenv func(string) string) (method oidc.LoginMethod, inferredDevice bool) {
	switch configured {
	case "device":
		return oidc.LoginDevice, false
	case "browser":
		return oidc.LoginBrowser, false
	default: // Kong restricts this field to auto, browser, or device.
		if getenv("SSH_CONNECTION") != "" || getenv("SSH_TTY") != "" {
			return oidc.LoginDevice, true
		}
		return oidc.LoginBrowser, false
	}
}

func loginMethodName(method oidc.LoginMethod) string {
	if method == oidc.LoginDevice {
		return "device"
	}
	return "browser"
}

type brokerProcess interface {
	Serve(context.Context) error
	Ready() <-chan struct{}
}

// runAgentCommand starts the broker before the child and tears it down when
// the child exits. Standard streams and the environment are inherited so an
// interactive shell behaves exactly as if it had been launched directly.
func runAgentCommand(ctx context.Context, cancel context.CancelFunc, b brokerProcess, argv []string) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- b.Serve(ctx) }()

	select {
	case <-b.Ready():
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		<-serveErr
		return fmt.Errorf("start %q: %w", argv[0], err)
	}

	childErr := cmd.Wait()
	cancel()
	brokerErr := <-serveErr
	if childErr != nil {
		return childProcessError{childErr}
	}
	if brokerErr != nil && brokerErr != context.Canceled {
		return fmt.Errorf("broker serve error: %w", brokerErr)
	}
	return nil
}

type childProcessError struct{ error }

func (e childProcessError) ExitCode() int {
	if exitErr, ok := e.error.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}
