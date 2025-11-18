package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/config"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type PolicyServerCLI struct {
	ConfigFile string `help:"Path to policy configuration file (YAML or CUE)" short:"c" required:"true"`
	Port       int    `help:"Port to listen on" short:"p" default:"9999"`
	CAPubkey   string `help:"CA public key (URL like http://localhost:8080, file path, or literal SSH key)" required:"true"`
}

func (c *PolicyServerCLI) Run(logger *slog.Logger) error {
	// Resolve CA public key
	caPubkey, err := resolveCAPubkey(c.CAPubkey)
	if err != nil {
		return err
	}

	// Load policy configuration
	logger.Info("loading policy configuration", "file", c.ConfigFile)
	cfg, err := config.LoadFromFile(c.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load policy config: %w", err)
	}

	// Validate configuration
	logger.Info("policy configuration loaded",
		"users", len(cfg.Users),
		"hosts", len(cfg.Hosts),
		"oidc_issuer", cfg.OIDC.Issuer,
		"oidc_audience", cfg.OIDC.Audience)

	// Create policy evaluator
	ctx := context.Background()
	eval, err := evaluator.New(ctx, cfg)
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

	addr := fmt.Sprintf(":%d", c.Port)
	logger.Info("starting policy server",
		"addr", addr,
		"config_file", c.ConfigFile,
		"ca_pubkey_length", len(caPubkey))

	return http.ListenAndServe(addr, r)
}
