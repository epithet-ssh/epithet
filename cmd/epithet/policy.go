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
	Issuer       string `help:"OIDC issuer URL" name:"issuer"`
	ClientID     string `help:"OIDC client ID" name:"client-id"`
	ClientSecret string `help:"OIDC client secret (for confidential clients)" name:"client-secret"`
}

// PolicyServerCLI defines the CLI flags for the policy server.
// Configuration comes from ~/.epithet/*.yaml under the "policy" section,
// or from command-line flags. Maps (users, hosts) can only come from config files.
type PolicyServerCLI struct {
	Listen string `help:"Address to listen on" short:"l" default:"0.0.0.0:9999"`

	// Embedded struct for OIDC - CLI flags are --oidc-issuer, --oidc-client-id, etc.
	// Config file uses nested policy.oidc.issuer (handled by loadPolicyFromCUE, allowed via AllowUnknownFields)
	OIDC PolicyOIDCConfig `embed:"" prefix:"oidc-"`

	// CA public key - can be URL, file path, or literal key
	CAPubkey string `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-pubkey"`

	// Default expiration
	DefaultExpiration string `help:"Default certificate expiration (e.g., 5m)" name:"default-expiration"`

	// Discovery base URL for CDN support
	DiscoveryBaseURL string `help:"Base URL for discovery endpoints (e.g., https://cdn.example.com)" name:"discovery-base-url"`

	// PolicySource is the URL/path to load dynamic policy from (users, hosts, defaults).
	// Can be http://, https://, file://, or a bare path. When set, policy is reloaded
	// on each request, enabling updates without server restart.
	PolicySource string `help:"URL/path to load policy from (http://, file://, or path)" name:"policy-source"`
}

func (c *PolicyServerCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config, unifiedConfig cue.Value) error {
	// Load server configuration from unified CUE config.
	serverCfg, err := c.loadServerConfigFromCUE(unifiedConfig)
	if err != nil {
		return fmt.Errorf("failed to load server config: %w", err)
	}

	// Apply CLI overrides for server config.
	c.applyServerOverrides(serverCfg)

	// Resolve CA public key (may fetch from URL).
	if serverCfg.CAPublicKey == "" {
		return fmt.Errorf("ca_pubkey is required (via --ca-pubkey flag or policy.ca_pubkey in config)")
	}
	caPubkey, err := resolveCAPubkey(serverCfg.CAPublicKey, tlsCfg, logger)
	if err != nil {
		return err
	}
	serverCfg.CAPublicKey = caPubkey

	// Validate server configuration.
	if err := serverCfg.Validate(); err != nil {
		return fmt.Errorf("invalid server config: %w", err)
	}

	ctx := context.Background()

	// Determine policy source: --policy-source flag, config file, or inline policy.
	policySource := c.PolicySource
	if policySource == "" {
		policySource = serverCfg.PolicyURL
	}

	var eval *evaluator.Evaluator
	var validator policyserver.TokenValidator
	var policyProvider policyserver.PolicyProvider

	if policySource != "" {
		// Dynamic policy mode: load policy from URL/file on each request.
		logger.Info("using dynamic policy loading", "source", policySource)

		loader := policyserver.NewPolicyLoader(policySource)
		policyProvider = policyserver.NewLoaderProvider(loader)

		// Validate we can load policy at startup.
		initialPolicy, err := loader.Load(ctx)
		if err != nil {
			return fmt.Errorf("failed to load initial policy from %s: %w", policySource, err)
		}

		logger.Info("initial policy loaded",
			"users", len(initialPolicy.Users),
			"hosts", len(initialPolicy.Hosts))

		eval, validator, err = evaluator.NewWithProvider(ctx, serverCfg, policyProvider, tlsCfg)
		if err != nil {
			return fmt.Errorf("failed to create policy evaluator: %w", err)
		}
	} else {
		// Static policy mode: load policy from inline config (backwards compatible).
		cfg, err := c.loadPolicyFromCUE(unifiedConfig)
		if err != nil {
			return fmt.Errorf("failed to load policy config: %w", err)
		}

		// Apply CLI overrides.
		c.applyOverrides(cfg)

		// Validate policy configuration.
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid policy config: %w", err)
		}

		logger.Info("policy configuration loaded (static)",
			"users", len(cfg.Users),
			"hosts", len(cfg.Hosts),
			"oidc_issuer", cfg.OIDC.Issuer,
			"oidc_client_id", cfg.OIDC.ClientID)

		eval, validator, err = evaluator.New(ctx, cfg, tlsCfg)
		if err != nil {
			return fmt.Errorf("failed to create policy evaluator: %w", err)
		}

		// Use static provider for discovery handlers.
		policyProvider = policyserver.NewStaticProvider(cfg.ExtractPolicyConfig())
	}

	// Create policy server handler.
	// Note: Discovery hashes are computed from current policy and may change with dynamic loading.
	// For now, we compute initial hashes; a future enhancement could make these dynamic.
	initialPolicy, err := policyProvider.GetPolicy(ctx)
	if err != nil {
		return fmt.Errorf("failed to get initial policy for hashes: %w", err)
	}

	authConfig := serverCfg.BootstrapAuth()
	matchPatterns := initialPolicy.HostPatterns()
	unauthHash := policyserver.ComputeUnauthDiscoveryHash(authConfig)
	authHash := policyserver.ComputeAuthDiscoveryHash(authConfig, matchPatterns)

	handler := policyserver.NewHandler(policyserver.Config{
		CAPublicKey:      sshcert.RawPublicKey(caPubkey),
		Validator:        validator,
		Evaluator:        eval,
		DiscoveryHash:    unauthHash,
		DiscoveryBaseURL: c.DiscoveryBaseURL,
	})

	// Create discovery handler.
	discoveryHandler := policyserver.NewDiscoveryHandler(policyserver.DiscoveryConfig{
		Validator:     validator,
		MatchPatterns: matchPatterns,
		UnauthHash:    unauthHash,
		AuthHash:      authHash,
		AuthConfig:    authConfig,
	})

	// Set up router with middleware.
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Post("/", handler)
	// Auth-aware discovery redirect: /d/current -> /d/{unauthHash} or /d/{authHash}
	// depending on whether Authorization header is present.
	r.Get("/d/current", policyserver.NewDiscoveryRedirectHandler(unauthHash, authHash, c.DiscoveryBaseURL))
	// Content-addressed endpoint: /d/{hash} (immutable, serves unauth or auth discovery based on hash).
	r.Get("/d/*", discoveryHandler)

	logger.Info("starting policy server",
		"listen", c.Listen,
		"ca_pubkey_length", len(caPubkey),
		"unauth_hash", unauthHash,
		"auth_hash", authHash,
		"match_patterns", matchPatterns,
		"dynamic_policy", policySource != "")

	return http.ListenAndServe(c.Listen, r)
}

// loadServerConfigFromCUE decodes the server configuration (static) from CUE config.
func (c *PolicyServerCLI) loadServerConfigFromCUE(unifiedConfig cue.Value) (*policyserver.ServerConfig, error) {
	// Look up policy section.
	policyVal := unifiedConfig.LookupPath(cue.ParsePath("policy"))
	if !policyVal.Exists() {
		// Return empty config - CLI flags will provide required values.
		return &policyserver.ServerConfig{}, nil
	}

	// Decode into ServerConfig.
	var cfg policyserver.ServerConfig
	if err := policyVal.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode server config: %w", err)
	}

	return &cfg, nil
}

// loadPolicyFromCUE decodes the policy section from the unified CUE config.
// This handles maps (users, hosts) that cannot be represented as CLI flags.
func (c *PolicyServerCLI) loadPolicyFromCUE(unifiedConfig cue.Value) (*policyserver.PolicyRulesConfig, error) {
	// Look up policy section.
	policyVal := unifiedConfig.LookupPath(cue.ParsePath("policy"))
	if !policyVal.Exists() {
		// Return empty config - CLI flags will provide required values.
		return &policyserver.PolicyRulesConfig{
			Users: make(map[string][]string),
		}, nil
	}

	// Decode into PolicyRulesConfig (CUE handles maps correctly).
	var cfg policyserver.PolicyRulesConfig
	if err := policyVal.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode policy config: %w", err)
	}

	// Ensure Users map is not nil.
	if cfg.Users == nil {
		cfg.Users = make(map[string][]string)
	}

	return &cfg, nil
}

// applyServerOverrides applies CLI-provided values over server config values.
func (c *PolicyServerCLI) applyServerOverrides(cfg *policyserver.ServerConfig) {
	if c.CAPubkey != "" {
		cfg.CAPublicKey = c.CAPubkey
	}
	if c.OIDC.Issuer != "" {
		cfg.OIDC.Issuer = c.OIDC.Issuer
	}
	if c.OIDC.ClientID != "" {
		cfg.OIDC.ClientID = c.OIDC.ClientID
	}
	if c.OIDC.ClientSecret != "" {
		cfg.OIDC.ClientSecret = c.OIDC.ClientSecret
	}
	if c.PolicySource != "" {
		cfg.PolicyURL = c.PolicySource
	}
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
	if c.OIDC.ClientID != "" {
		cfg.OIDC.ClientID = c.OIDC.ClientID
	}
	if c.OIDC.ClientSecret != "" {
		cfg.OIDC.ClientSecret = c.OIDC.ClientSecret
	}
	if c.DefaultExpiration != "" {
		if cfg.Defaults == nil {
			cfg.Defaults = &policyserver.DefaultPolicy{}
		}
		cfg.Defaults.Expiration = c.DefaultExpiration
	}
}

// resolveCAPubkey resolves the CA public key from a URL, file path, or literal key
func resolveCAPubkey(input string, tlsCfg tlsconfig.Config, logger *slog.Logger) (string, error) {
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
