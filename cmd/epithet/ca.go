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
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

type CACLI struct {
	Policy  string `help:"URL for policy service" short:"p" env:"POLICY_URL" required:"true"`
	Key     string `help:"Path to ca private key" short:"k" default:"/etc/epithet/ca.key"`
	Address string `help:"Address to bind to" short:"a" env:"PORT" default:"0.0.0.0:8080"`
}

func (c *CACLI) Run(logger *slog.Logger) error {
	logger.Debug("ca command called", "ca", c)

	// Read CA private key
	privKey, err := os.ReadFile(c.Key)
	if err != nil {
		return fmt.Errorf("unable to load ca key: %w", err)
	}
	logger.Info("ca_key", "path", c.Key)
	logger.Info("policy_url", "url", c.Policy)

	// Create CA
	caInstance, err := ca.New(sshcert.RawPrivateKey(string(privKey)), c.Policy)
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

	r.Handle("/", caserver.New(caInstance, logger, nil))

	logger.Info("listening", "address", c.Address)
	err = http.ListenAndServe(c.Address, r)
	if err != nil {
		return err
	}

	return nil
}
