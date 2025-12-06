package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"cuelang.org/go/encoding/yaml"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type PolicyServerCLI struct {
	ConfigFile string `help:"Path to policy configuration file (YAML or CUE)" short:"c" required:"true"`
	Listen     string `help:"Address to listen on" short:"l" default:"0.0.0.0:9999"`
	CAPubkey   string `help:"CA public key (URL like http://localhost:8080, file path, or literal SSH key)" required:"true"`
}

func (c *PolicyServerCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	// Resolve CA public key (may fetch from URL)
	caPubkey, err := resolveCAPubkey(c.CAPubkey, tlsCfg)
	if err != nil {
		return err
	}

	// Load policy configuration
	logger.Info("loading policy configuration", "file", c.ConfigFile)
	cfg, err := loadPolicyConfig(c.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load policy config: %w", err)
	}

	// Validate policy configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid policy config: %w", err)
	}

	// Validate configuration
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
		CAPublicKey: sshcert.RawPublicKey(caPubkey),
		Evaluator:   eval,
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
		"config_file", c.ConfigFile,
		"ca_pubkey_length", len(caPubkey))

	return http.ListenAndServe(c.Listen, r)
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

// loadPolicyConfig loads policy configuration from a file (YAML, JSON, or CUE).
func loadPolicyConfig(path string) (*policyserver.PolicyRulesConfig, error) {
	ctx := cuecontext.New()

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	var val cue.Value

	// Handle directories and .cue files using load.Instances
	if fileInfo.IsDir() || strings.HasSuffix(strings.ToLower(path), ".cue") {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path: %w", err)
		}

		cfg := &load.Config{
			Dir:       filepath.Dir(absPath),
			DataFiles: true,
		}

		var args []string
		if fileInfo.IsDir() {
			args = []string{path}
		} else {
			args = []string{absPath}
		}

		instances := load.Instances(args, cfg)
		if len(instances) == 0 {
			return nil, fmt.Errorf("no instances loaded from %s", path)
		}

		inst := instances[0]
		if inst.Err != nil {
			return nil, fmt.Errorf("failed to load config: %w", inst.Err)
		}

		val = ctx.BuildInstance(inst)
		if err := val.Err(); err != nil {
			return nil, fmt.Errorf("failed to build CUE value: %w", err)
		}
	} else {
		// Handle standalone data files (YAML, JSON)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".yaml", ".yml":
			file, err := yaml.Extract("", data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse YAML: %w", err)
			}
			val = ctx.BuildFile(file)
		case ".json":
			val = ctx.CompileBytes(data)
		default:
			// Try YAML as default
			file, err := yaml.Extract("", data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse file: %w", err)
			}
			val = ctx.BuildFile(file)
		}

		if err := val.Err(); err != nil {
			return nil, fmt.Errorf("failed to build CUE value: %w", err)
		}
	}

	// Decode into PolicyRulesConfig
	var config policyserver.PolicyRulesConfig
	if err := val.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return &config, nil
}
