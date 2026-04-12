package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// PolicyOIDCConfig holds OIDC configuration for the policy server.
type PolicyOIDCConfig struct {
	Issuer       string `help:"OIDC issuer URL" name:"issuer"`
	ClientID     string `help:"OIDC client ID" name:"client-id"`
	ClientSecret string `help:"OIDC client secret (for confidential clients)" name:"client-secret"`
}

// PolicyServerCLI defines the CLI flags for the policy server.
// Scalar configuration comes from CLI flags, env vars, or config files
// (resolved by Kong in that precedence order). Map data (users, hosts)
// can only come from config files or --policy-source.
type PolicyServerCLI struct {
	Listen string `help:"Address to listen on" short:"l" default:"0.0.0.0:9999"`

	OIDC PolicyOIDCConfig `embed:"" prefix:"oidc-"`

	CAPubkey string `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-pubkey"`

	DefaultExpiration string `help:"Default certificate expiration (e.g., 5m)" name:"default-expiration"`

	PolicySource string `help:"URL/path to load policy from (http://, file://, or path)" name:"policy-source"`
}

func (c *PolicyServerCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	// Build server config from CLI/config-file resolved fields.
	serverCfg := &policyserver.ServerConfig{
		CAPublicKey: c.CAPubkey,
		OIDC: policyserver.OIDCConfig{
			Issuer:       c.OIDC.Issuer,
			ClientID:     c.OIDC.ClientID,
			ClientSecret: c.OIDC.ClientSecret,
		},
		PolicyURL: c.PolicySource,
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

	ctx := context.Background()

	var eval *evaluator.Evaluator
	var validator policyserver.TokenValidator
	var policyProvider policyserver.PolicyProvider

	if c.PolicySource != "" {
		// Dynamic policy mode: load policy from URL/file on each request.
		logger.Info("using dynamic policy loading", "source", c.PolicySource)

		loader := policyserver.NewPolicyLoader(c.PolicySource)
		policyProvider = policyserver.NewLoaderProvider(loader)

		initialPolicy, err := loader.Load(ctx)
		if err != nil {
			return fmt.Errorf("failed to load initial policy from %s: %w", c.PolicySource, err)
		}

		logger.Info("initial policy loaded",
			"users", len(initialPolicy.Users),
			"hosts", len(initialPolicy.Hosts))

		eval, validator, err = evaluator.NewWithProvider(ctx, serverCfg, policyProvider, tlsCfg)
		if err != nil {
			return fmt.Errorf("failed to create policy evaluator: %w", err)
		}
	} else {
		// Static policy mode: load policy maps from inline config.
		cfg, err := c.loadInlinePolicy()
		if err != nil {
			return fmt.Errorf("failed to load policy config: %w", err)
		}

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

		policyProvider = policyserver.NewStaticProvider(cfg.ExtractPolicyConfig())
	}

	initialPolicy, err := policyProvider.GetPolicy(ctx)
	if err != nil {
		return fmt.Errorf("failed to get initial policy: %w", err)
	}

	authConfig := serverCfg.BootstrapAuth()
	matchPatterns := initialPolicy.HostPatterns()

	// Build discovery response that the CA will fetch via GET /.
	discovery := &policyserver.DiscoveryResponse{
		Auth:          &authConfig,
		MatchPatterns: matchPatterns,
	}
	if c.DefaultExpiration != "" {
		discovery.DefaultExpiration = c.DefaultExpiration
	}

	handler := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: sshcert.RawPublicKey(caPubkey),
		Validator:   validator,
		Evaluator:   eval,
		Discovery:   discovery,
	})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Single handler for both GET (discovery) and POST (cert evaluation).
	r.Handle("/", handler)

	logger.Info("starting policy server",
		"listen", c.Listen,
		"ca_pubkey_length", len(caPubkey),
		"match_patterns", matchPatterns,
		"dynamic_policy", c.PolicySource != "")

	return listenAndServe(c.Listen, r)
}

// loadInlinePolicy loads policy maps (users, hosts, defaults) from config files.
// Scalar fields (ca-pubkey, oidc, etc.) are already resolved by Kong.
func (c *PolicyServerCLI) loadInlinePolicy() (*policyserver.PolicyRulesConfig, error) {
	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: c.CAPubkey,
		OIDC: policyserver.OIDCConfig{
			Issuer:       c.OIDC.Issuer,
			ClientID:     c.OIDC.ClientID,
			ClientSecret: c.OIDC.ClientSecret,
		},
		Users: make(map[string][]string),
	}

	// Load map data from config files' "policy" section.
	configPaths := configFilePaths()
	if err := config.LoadSection(configPaths, "policy", cfg); err != nil {
		return nil, err
	}

	// Re-apply CLI-resolved scalar fields over anything LoadSection decoded,
	// since Kong's precedence (CLI > config) is authoritative for these.
	cfg.CAPublicKey = c.CAPubkey
	cfg.OIDC.Issuer = c.OIDC.Issuer
	cfg.OIDC.ClientID = c.OIDC.ClientID
	cfg.OIDC.ClientSecret = c.OIDC.ClientSecret
	if c.DefaultExpiration != "" {
		if cfg.Defaults == nil {
			cfg.Defaults = &policyserver.DefaultPolicy{}
		}
		cfg.Defaults.Expiration = c.DefaultExpiration
	}

	if cfg.Users == nil {
		cfg.Users = make(map[string][]string)
	}

	return cfg, nil
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
