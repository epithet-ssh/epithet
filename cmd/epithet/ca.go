package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type CACLI struct {
	Policy string `help:"URL for policy service" short:"p" env:"POLICY_URL" required:"true"`
	Key    string `help:"Path to ca private key" short:"k" default:"/etc/epithet/ca.key"`
	Listen string `help:"Address to listen on" short:"l" env:"PORT" default:"0.0.0.0:8080"`
}

func (c *CACLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	logger.Debug("ca command called", "ca", c)

	// Validate policy URL requires TLS (unless --insecure)
	if err := tlsCfg.ValidateURL(c.Policy); err != nil {
		return err
	}

	// Read CA private key
	privKey, err := os.ReadFile(c.Key)
	if err != nil {
		return fmt.Errorf("unable to load ca key: %w", err)
	}
	logger.Info("ca_key", "path", c.Key)
	logger.Info("policy_url", "url", c.Policy)

	// Create CA
	caInstance, err := ca.New(sshcert.RawPrivateKey(string(privKey)), c.Policy, ca.WithTLSConfig(tlsCfg), ca.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("unable to create CA: %w", err)
	}

	// Set up HTTP router
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Create certificate logger for audit trail
	certLogger := caserver.NewSlogCertLogger(logger)

	r.Handle("/", caserver.New(caInstance, logger, nil, certLogger))

	logger.Info("listening", "address", c.Listen)
	err = http.ListenAndServe(c.Listen, r)
	if err != nil {
		return err
	}

	return nil
}
