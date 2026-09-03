package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/inventory"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/policyserver/writpolicy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
)

// PolicyOIDCConfig holds OIDC configuration for the policy server.
type PolicyOIDCConfig struct {
	Issuer       string `help:"OIDC issuer URL" name:"issuer"`
	ClientID     string `help:"OIDC client ID" name:"client-id"`
	ClientSecret string `help:"OIDC client secret (for confidential clients)" name:"client-secret"`
}

// PolicyServerCLI defines the CLI flags for the policy server.
// Configuration comes from CLI flags, env vars, or config files
// (resolved by Kong in that precedence order); config-file keys under
// `policy:` use the flag names verbatim (kebab-case).
type PolicyServerCLI struct {
	Listen string `help:"Address to listen on" short:"l" default:"0.0.0.0:9999"`

	OIDC PolicyOIDCConfig `embed:"" prefix:"oidc-"`

	CAPubkey string `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-pubkey"`

	PolicyFile string `help:"Path to the writ policy file" name:"policy-file"`

	Inventory []string `help:"Inventory file path or glob (repeatable)" name:"inventory"`

	PrincipalMode string `help:"Default SSH certificate principal mode" name:"principal-mode" default:"account-name" enum:"account-name,epithet-principal-v1"`

	Extension map[string]string `help:"Certificate extension for issued certs (name=value, repeatable; default permit-pty, permit-agent-forwarding, permit-user-rc)" name:"extension"`

	DefaultExpiration string `help:"Default certificate expiration when no rule sets a ttl (e.g., 5m)" name:"default-expiration"`

	Check bool `help:"Validate the policy and inventory, then exit" name:"check"`
}

func (c *PolicyServerCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	eval, err := c.buildEvaluator(logger)
	if err != nil {
		return err
	}

	if c.Check {
		fmt.Println("policy and inventory OK")
		return nil
	}

	// Build server config from CLI/config-file resolved fields.
	serverCfg := &policyserver.ServerConfig{
		CAPublicKey: c.CAPubkey,
		OIDC: policyserver.OIDCConfig{
			Issuer:       c.OIDC.Issuer,
			ClientID:     c.OIDC.ClientID,
			ClientSecret: c.OIDC.ClientSecret,
		},
	}

	// Resolve CA public key (may fetch from URL).
	if serverCfg.CAPublicKey == "" {
		return fmt.Errorf("ca-pubkey is required (via --ca-pubkey flag or policy.ca-pubkey in config)")
	}
	caPubkey, err := resolveCAPubkey(serverCfg.CAPublicKey, tlsCfg, logger)
	if err != nil {
		return err
	}
	serverCfg.CAPublicKey = caPubkey

	if err := serverCfg.Validate(); err != nil {
		return fmt.Errorf("invalid server config: %w", err)
	}

	validator, err := oidc.NewValidator(context.Background(), oidc.Config{
		Issuer:    serverCfg.OIDC.Issuer,
		ClientID:  serverCfg.OIDC.ClientID,
		TLSConfig: tlsCfg,
	})
	if err != nil {
		return fmt.Errorf("failed to create OIDC validator: %w", err)
	}

	authConfig := serverCfg.BootstrapAuth()

	// Build discovery response that the CA will fetch via GET /.
	discovery := &wire.Discovery{Auth: &authConfig}

	handler, err := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: sshcert.RawPublicKey(caPubkey),
		Validator:   validator,
		Evaluator:   eval,
		Discovery:   discovery,
	})
	if err != nil {
		return fmt.Errorf("failed to create policy handler: %w", err)
	}

	// net/http.Server already recovers handler panics per-request (see
	// listenAndServe), so no Recoverer middleware is needed.
	r := http.NewServeMux()

	// Single handler for both GET (discovery) and POST (cert evaluation).
	r.Handle("/", handler)

	logger.Info("starting policy server",
		"listen", c.Listen,
		"policy_file", c.PolicyFile,
		"ca_pubkey_length", len(caPubkey))

	return listenAndServe(c.Listen, r)
}

// buildEvaluator loads the writ policy and static inventory and wires
// the evaluator with an empty plugin registry — a policy that names any
// requirement, flag, or notify target therefore fails here, at
// startup, naming what is missing. Shared by --check and the server
// path; reload is a process restart.
func (c *PolicyServerCLI) buildEvaluator(logger *slog.Logger) (*writpolicy.Evaluator, error) {
	if c.PolicyFile == "" {
		return nil, fmt.Errorf("policy-file is required (via --policy-file flag or policy.policy-file in config)")
	}
	src, err := os.ReadFile(c.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	pol, diags := writ.Load(string(src))
	for _, d := range diag.Warnings(diags) {
		logger.Warn("policy warning", "pos", fmt.Sprintf("%s:%s", c.PolicyFile, d.Pos), "msg", d.Msg)
	}
	if pol == nil {
		errs := diag.Errors(diags)
		for _, d := range errs {
			fmt.Fprintf(os.Stderr, "%s:%s: error: %s\n", c.PolicyFile, d.Pos, d.Msg)
		}
		return nil, fmt.Errorf("policy %s has %d error(s)", c.PolicyFile, len(errs))
	}

	if len(c.Inventory) == 0 {
		return nil, fmt.Errorf("inventory is required (via --inventory flag or policy.inventory in config)")
	}
	paths, err := config.ExpandGlobs(c.Inventory)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no inventory files match %s", strings.Join(c.Inventory, ", "))
	}
	inv, err := inventory.NewStatic(paths,
		inventory.WithDefaultPrincipalMode(inventory.PrincipalMode(c.PrincipalMode)))
	if err != nil {
		return nil, err
	}

	opts := writpolicy.Options{}
	if len(c.Extension) > 0 {
		opts.Extensions = c.Extension
	}
	if c.DefaultExpiration != "" {
		d, err := time.ParseDuration(c.DefaultExpiration)
		if err != nil {
			return nil, fmt.Errorf("invalid default-expiration: %w", err)
		}
		opts.DefaultTTL = d
	}

	eval, warnings, err := writpolicy.New(pol, inv, &writpolicy.Registry{}, opts)
	if err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	for _, w := range warnings {
		logger.Warn("policy warning", "msg", w)
	}

	logger.Info("policy loaded",
		"policy_file", c.PolicyFile,
		"allow_rules", len(pol.Allows),
		"deny_rules", len(pol.Denies),
		"inventory_files", len(paths))
	return eval, nil
}

// resolveCAPubkey resolves the CA public key from a URL, file path, or literal key.
func resolveCAPubkey(input string, tlsCfg tlsconfig.Config, logger *slog.Logger) (string, error) {
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if err := tlsCfg.ValidateURL(input); err != nil {
			return "", err
		}

		httpClient, err := tlsconfig.NewHTTPClient(tlsCfg)
		if err != nil {
			return "", fmt.Errorf("failed to create HTTP client: %w", err)
		}

		if logger != nil {
			logger.Debug("http request", "method", "GET", "url", input)
		}

		start := time.Now()
		resp, err := httpClient.Get(input)
		duration := time.Since(start)
		if err != nil {
			if logger != nil {
				logger.Debug("http request failed", "method", "GET", "url", input, "duration_ms", duration.Milliseconds(), "error", err)
			}
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: %w", input, err)
		}
		defer resp.Body.Close()

		if logger != nil {
			logger.Debug("http response", "method", "GET", "url", input, "status", resp.StatusCode, "duration_ms", duration.Milliseconds())
		}

		if resp.StatusCode != 200 {
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: status %d", input, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from URL %s: %w", input, err)
		}

		return strings.TrimSpace(string(body)), nil
	}

	if _, err := os.Stat(input); err == nil {
		body, err := os.ReadFile(input)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from file %s: %w", input, err)
		}
		return strings.TrimSpace(string(body)), nil
	}

	if !strings.HasPrefix(input, "ssh-") && !strings.HasPrefix(input, "ecdsa-") {
		return "", fmt.Errorf("CA public key does not appear to be a valid SSH key (should start with ssh-* or ecdsa-*), not a valid URL, and file does not exist: %s", input)
	}

	return input, nil
}
