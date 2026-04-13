package main

import (
	"context"
	"fmt"
	"log/slog"
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

	// Validate policy URL requires TLS (unless --insecure).
	if err := tlsCfg.ValidateURL(c.Policy); err != nil {
		return err
	}

	// Read CA private key.
	privKey, err := os.ReadFile(c.Key)
	if err != nil {
		return fmt.Errorf("unable to load ca key: %w", err)
	}
	logger.Info("ca_key", "path", c.Key)
	logger.Info("policy_url", "url", c.Policy)

	// Create CA.
	caInstance, err := ca.New(sshcert.RawPrivateKey(string(privKey)), c.Policy, ca.WithTLSConfig(tlsCfg), ca.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("unable to create CA: %w", err)
	}

	// Set up HTTP router.
	r := chi.NewRouter()

	// Middleware stack.
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Create certificate logger for audit trail.
	// Audit logs always emit at Info regardless of global verbosity.
	certLogger := caserver.NewSlogCertLogger(certAuditLogger(logger))

	server := caserver.New(caInstance, logger, nil, certLogger)
	r.Handle("/", server.Handler())
	r.Handle("/discovery", server.DiscoveryHandler())

	logger.Info("listening", "address", c.Listen)
	return listenAndServe(c.Listen, r)
}

// certAuditLogger returns a logger that emits at Info or below, regardless of
// the parent logger's level. Audit events like certificate issuance must
// always be logged.
func certAuditLogger(parent *slog.Logger) *slog.Logger {
	return slog.New(&minLevelHandler{
		inner:    parent.Handler(),
		minLevel: slog.LevelInfo,
	})
}

// minLevelHandler wraps an slog.Handler, overriding Enabled to accept
// records at or above minLevel even if the inner handler would suppress them.
type minLevelHandler struct {
	inner    slog.Handler
	minLevel slog.Level
}

func (h *minLevelHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.minLevel
}

func (h *minLevelHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

func (h *minLevelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &minLevelHandler{inner: h.inner.WithAttrs(attrs), minLevel: h.minLevel}
}

func (h *minLevelHandler) WithGroup(name string) slog.Handler {
	return &minLevelHandler{inner: h.inner.WithGroup(name), minLevel: h.minLevel}
}
