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

	"cuelang.org/go/cue"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// PolicyOIDCConfig holds OIDC configuration for the policy server.
// This is embedded in PolicyServerCLI to enable nested config paths like policy.oidc.issuer
type PolicyOIDCConfig struct {
	Issuer   string `help:"OIDC issuer URL" name:"issuer"`
	Audience string `help:"OIDC audience (client ID)" name:"audience"`
}

// PolicyServerCLI defines the CLI flags for the policy server.
// Configuration comes from ~/.epithet/*.yaml under the "policy" section,
// or from command-line flags. Maps (users, hosts) can only come from config files.
type PolicyServerCLI struct {
	Listen string `help:"Address to listen on" short:"l" default:"0.0.0.0:9999"`

	// Nested struct for OIDC - gives us policy.oidc.issuer in config
	OIDC PolicyOIDCConfig `embed:"" prefix:"oidc-"`

	// CA public key - can be URL, file path, or literal key
	CAPubkey string `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-pubkey"`

	// Default expiration
	DefaultExpiration string `help:"Default certificate expiration (e.g., 5m)" name:"default-expiration"`
}

func (c *PolicyServerCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config, unifiedConfig cue.Value) error {
	// Load policy configuration from unified CUE config (handles maps like users, hosts)
	cfg, err := c.loadPolicyFromCUE(unifiedConfig)
	if err != nil {
		return fmt.Errorf("failed to load policy config: %w", err)
	}

	// Apply CLI overrides (scalar values take precedence over config file)
	c.applyOverrides(cfg)

	// Resolve CA public key (may fetch from URL)
	if cfg.CAPublicKey == "" {
		return fmt.Errorf("ca_pubkey is required (via --ca-pubkey flag or policy.ca_pubkey in config)")
	}
	caPubkey, err := resolveCAPubkey(cfg.CAPublicKey, tlsCfg)
	if err != nil {
		return err
	}
	cfg.CAPublicKey = caPubkey

	// Validate policy configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid policy config: %w", err)
	}

	logger.Info("policy configuration loaded",
		"users", len(cfg.Users),
		"hosts", len(cfg.Hosts),
		"oidc_issuer", cfg.OIDC.Issuer,
		"oidc_audience", cfg.OIDC.Audience)

	// Create policy evaluator
	ctx := context.Background()
	eval, err := evaluator.New(ctx, cfg, tlsCfg)
	if err != nil {
		return fmt.Errorf("failed to create policy evaluator: %w", err)
	}

	// Create policy server handler
	handler := policyserver.NewHandler(policyserver.Config{
		CAPublicKey:   sshcert.RawPublicKey(caPubkey),
		Evaluator:     eval,
		DiscoveryHash: cfg.DiscoveryHash(),
	})

	// Set up router with middleware
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Post("/", handler)

	logger.Info("starting policy server",
		"listen", c.Listen,
		"ca_pubkey_length", len(caPubkey),
		"discovery_hash", cfg.DiscoveryHash())

	return http.ListenAndServe(c.Listen, r)
}

// loadPolicyFromCUE decodes the policy section from the unified CUE config.
// This handles maps (users, hosts) that cannot be represented as CLI flags.
func (c *PolicyServerCLI) loadPolicyFromCUE(unifiedConfig cue.Value) (*policyserver.PolicyRulesConfig, error) {
	// Look up policy section
	policyVal := unifiedConfig.LookupPath(cue.ParsePath("policy"))
	if !policyVal.Exists() {
		// Return empty config - CLI flags will provide required values
		return &policyserver.PolicyRulesConfig{
			Users: make(map[string][]string),
		}, nil
	}

	// Decode into PolicyRulesConfig (CUE handles maps correctly)
	var cfg policyserver.PolicyRulesConfig
	if err := policyVal.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode policy config: %w", err)
	}

	// Ensure Users map is not nil
	if cfg.Users == nil {
		cfg.Users = make(map[string][]string)
	}

	return &cfg, nil
}

// applyOverrides applies CLI-provided values over config file values.
// Only non-empty CLI values override the config.
func (c *PolicyServerCLI) applyOverrides(cfg *policyserver.PolicyRulesConfig) {
	if c.CAPubkey != "" {
		cfg.CAPublicKey = c.CAPubkey
	}
	if c.OIDC.Issuer != "" {
		cfg.OIDC.Issuer = c.OIDC.Issuer
	}
	if c.OIDC.Audience != "" {
		cfg.OIDC.Audience = c.OIDC.Audience
	}
	if c.DefaultExpiration != "" {
		if cfg.Defaults == nil {
			cfg.Defaults = &policyserver.DefaultPolicy{}
		}
		cfg.Defaults.Expiration = c.DefaultExpiration
	}
}

// resolveCAPubkey resolves the CA public key from a URL, file path, or literal key
func resolveCAPubkey(input string, tlsCfg tlsconfig.Config) (string, error) {
	// Check if it's a URL
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		// Validate URL requires TLS (unless --insecure)
		if err := tlsCfg.ValidateURL(input); err != nil {
			return "", err
		}

		// Create HTTP client with TLS config
		httpClient, err := tlsconfig.NewHTTPClient(tlsCfg)
		if err != nil {
			return "", fmt.Errorf("failed to create HTTP client: %w", err)
		}

		resp, err := httpClient.Get(input)
		if err != nil {
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: %w", input, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: status %d", input, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from URL %s: %w", input, err)
		}

		return strings.TrimSpace(string(body)), nil
	}

	// Check if it's a file path (exists on filesystem)
	if _, err := os.Stat(input); err == nil {
		body, err := os.ReadFile(input)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from file %s: %w", input, err)
		}
		return strings.TrimSpace(string(body)), nil
	}

	// Assume it's a literal SSH public key
	// Basic validation: should start with ssh-
	if !strings.HasPrefix(input, "ssh-") && !strings.HasPrefix(input, "ecdsa-") {
		return "", fmt.Errorf("CA public key does not appear to be a valid SSH key (should start with ssh-* or ecdsa-*), not a valid URL, and file does not exist: %s", input)
	}

	return input, nil
}
