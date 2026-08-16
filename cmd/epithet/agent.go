package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	authoidc "github.com/epithet-ssh/epithet/pkg/auth/oidc"
	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/caclient"
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

// acquireProfileLock takes an exclusive, non-blocking flock on
// <runDir>/agent.lock so at most one agent process ever owns a given
// profile's rundir: two agents sharing a rundir would race on
// removing/recreating the live broker socket (startBrokerListener does an
// os.Remove before listening), silently orphaning whichever one loses.
// Returning early with a clear error is much better than that.
//
// The returned file's fd is intentionally never closed or unlocked here:
// holding it open for the life of the process is exactly what pins the
// lock, and the OS releases the flock automatically when the process exits
// (normally or via signal), which is precisely when the lock should be
// released. Callers must keep the returned *os.File reachable for as long
// as the lock needs to be held (see runtime.KeepAlive at the call site) —
// otherwise the os.File finalizer could close the fd, and the lock with it,
// while the process is still running.
func acquireProfileLock(runDir, name string) (*os.File, error) {
	lockPath := filepath.Join(runDir, "agent.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("profile %q is already running (use --name to run a second profile)", name)
	}
	return f, nil
}

// AgentCLI is the parent command for agent-related subcommands.
// Shared flags are defined here and inherited by subcommands.
type AgentCLI struct {
	Name       string        `help:"Profile name; names the rundir and the ssh Tag (epithet-<name>, or just epithet for the default profile)" default:"default"`
	CaURL      []string      `help:"CA URL (repeatable, format: priority=N:https://url or https://url)" name:"ca-url" short:"c"`
	CaTimeout  time.Duration `help:"Per-request timeout for CA requests" name:"ca-timeout" default:"15s"`
	CaCooldown time.Duration `help:"Circuit breaker cooldown for failed CAs" name:"ca-cooldown" default:"10m"`

	Start   AgentStartCLI   `cmd:"" default:"withargs" help:"Start the epithet agent"`
	Inspect AgentInspectCLI `cmd:"inspect" help:"Inspect broker state (certificates, agents)"`
}

// AgentStartCLI is the default subcommand that starts the agent/broker.
type AgentStartCLI struct{}

func (s *AgentStartCLI) Run(parent *AgentCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	// Validate required fields for start
	if len(parent.CaURL) == 0 {
		return fmt.Errorf("--ca-url is required (at least one)")
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
	// --name (e.g. two shells both using the "default" profile) would
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
	if err != nil || discovery == nil || discovery.Auth == nil {
		return fmt.Errorf("failed to get discovery config from CA: %w", err)
	}
	logger.Info("discovered auth config from CA", "issuer", discovery.Auth.Issuer)

	oidcCfg := authoidc.Config{
		IssuerURL:    discovery.Auth.Issuer,
		ClientID:     discovery.Auth.ClientID,
		ClientSecret: discovery.Auth.ClientSecret,
		TLSConfig:    tlsCfg,
	}
	// Refresh state lives in this closure, in memory only. broker.Auth
	// serializes invocations, so no locking is needed here.
	var oauthState *oauth2.Token
	tokenFn := func(ctx context.Context, out io.Writer, force bool) (string, error) {
		if force && oauthState != nil {
			// The broker calls us with force=true only after the CA rejected a
			// token, i.e. after 401'ing on the id_token derived from this exact
			// oauthState. Authenticate treats a time-valid access token as
			// reusable and would hand back that same rejected id_token, so we
			// backdate its expiry to force the refresh-token (or full re-auth)
			// path, which mints a genuinely new id_token.
			oauthState.Expiry = time.Now().Add(-time.Minute)
		}
		idToken, next, err := authoidc.Authenticate(ctx, oidcCfg, oauthState, out)
		if err != nil {
			return "", err
		}
		oauthState = next
		return idToken, nil
	}

	// Create broker
	b, err := broker.New(*logger, brokerSock, tokenFn, caClient, agentDir)
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

	// Start broker
	logger.Info("starting broker", "socket", brokerSock)
	err = b.Serve(ctx)
	if err != nil && err != context.Canceled {
		return fmt.Errorf("broker serve error: %w", err)
	}

	logger.Info("broker shutdown complete")
	return nil
}

// profileTag returns the ssh Tag token for a profile. The default profile
// gets the bare "epithet" tag for ergonomics; named profiles get
// "epithet-<name>". Match tagged does exact-string matching, so the bare tag
// cannot collide with any suffixed one.
func profileTag(name string) string {
	if name == "default" {
		return "epithet"
	}
	return "epithet-" + name
}

// generateSSHConfig writes an SSH config file for this profile. The block is
// gated by "Match tagged epithet-<name>" rather than a bare Match exec so
// that multiple profiles' generated configs can coexist: ssh only evaluates
// a profile's exec line for hosts the user opted into via a Tag directive in
// their own Host blocks, keyed by this profile's name.
func (a *AgentCLI) generateSSHConfig(path, agentDir, brokerSock, homeDir string) error {
	// Find epithet binary path
	epithetPath, err := os.Executable()
	if err != nil {
		epithetPath = "epithet" // fallback to PATH
	}

	// Full home directory in the include pattern since ssh_config doesn't expand ~.
	includePattern := filepath.Join(homeDir, ".epithet", "run", "*", "ssh-config.conf")
	tag := profileTag(a.Name)

	// We only set IdentityAgent to point to the per-connection agent. This allows normal
	// fallback to ~/.ssh/id_* keys and password auth if epithet certificates aren't available,
	// which is important for production failure recovery.
	config := fmt.Sprintf(`# Generated by epithet agent - do not edit manually
# Profile: %s
#
# In ~/.ssh/config, tag the hosts this profile should handle, then include
# epithet's generated config AFTER the Tag lines (tags must be set before
# Match tagged is evaluated):
#
#   Host *.example.com
#       Tag %s
#   Include %s
#
# Requires OpenSSH 9.4 or newer (Tag / Match tagged).

Match tagged %s exec "%s match --host '%%h' --port '%%p' --user '%%r' --jump '%%j' --hash '%%C' --broker '%s'"
    IdentityAgent %s/%%C
`,
		a.Name,
		tag,
		includePattern,
		tag,
		epithetPath,
		brokerSock,
		agentDir,
	)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Truncate-and-rewrite: the rundir is named for the profile and persists
	// across restarts, so each start must overwrite any config left by a
	// prior run rather than assuming the file doesn't exist yet.
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write SSH config: %w", err)
	}

	return nil
}

// checkSSHConfigInclude checks if ~/.ssh/config contains the Include directive for epithet
func checkSSHConfigInclude(homeDir, includePattern, name string, logger *slog.Logger) error {
	sshConfigPath := filepath.Join(homeDir, ".ssh", "config")

	// Read SSH config file
	content, err := os.ReadFile(sshConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debug("~/.ssh/config does not exist", "path", sshConfigPath)
			return fmt.Errorf("SSH config not found")
		}
		return fmt.Errorf("failed to read SSH config: %w", err)
	}

	// Walk line by line (case-insensitive, flexible whitespace), tracking the
	// first Tag line so we can warn if the epithet Include precedes it: ssh
	// evaluates "Match tagged" against whatever tags are already set, so an
	// Include line above every Tag line would never see the tag activated.
	firstTagLineNum := -1
	includeLineNum := -1
	lineNum := 0
	lines := strings.SplitSeq(string(content), "\n")
	for line := range lines {
		lineNum++
		trimmed := strings.TrimSpace(line)
		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		if firstTagLineNum == -1 && strings.HasPrefix(lower, "tag ") {
			firstTagLineNum = lineNum
		}
		// Check for Include directive (case-insensitive)
		if strings.HasPrefix(lower, "include ") {
			// Extract the path after "Include"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				includePath := parts[1]
				// Expand ~ if present
				if strings.HasPrefix(includePath, "~/") {
					includePath = filepath.Join(homeDir, includePath[2:])
				}
				// Check if it matches our pattern
				if includePath == includePattern && includeLineNum == -1 {
					includeLineNum = lineNum
				}
			}
		}
	}

	if includeLineNum == -1 {
		return fmt.Errorf("Include directive not found")
	}

	logger.Debug("found epithet Include directive in ~/.ssh/config")
	switch {
	case firstTagLineNum == -1:
		// The Include is present but the user never wrote a Tag line at all —
		// the single most likely real-world misconfiguration, and one that
		// otherwise fails completely silently (epithet just never activates).
		logger.Warn(fmt.Sprintf("no 'Tag %s' lines found in ~/.ssh/config — epithet will never activate; tag the Host blocks it should handle", profileTag(name)))
	case includeLineNum < firstTagLineNum:
		logger.Warn("Include must come after Tag lines or epithet will never activate")
	}
	return nil
}
