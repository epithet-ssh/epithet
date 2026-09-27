package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

type CACLI struct {
	ControlPublicURL string `help:"Client-accessible control URL advertised at bootstrap" name:"control-public-url"`

	Inventory    string            `help:"URL for inventory service" name:"inventory" required:"true"`
	Directory    string            `help:"Directory service URL" name:"directory" required:"true"`
	OIDC         ServiceOIDCConfig `embed:"" prefix:"oidc-"`
	PolicyConfig `embed:""`

	Key    string `help:"Path to ca private key" short:"k" default:"/etc/epithet/ca.key"`
	Listen string `help:"Address to listen on" short:"l" env:"PORT" default:"0.0.0.0:8080"`
}

func (c *CACLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	logger.Debug("ca command called")

	// Read CA private key.
	privKey, err := os.ReadFile(c.Key)
	if err != nil {
		return fmt.Errorf("unable to load ca key: %w", err)
	}
	logger.Info("ca_key", "path", c.Key)

	evaluator, err := c.buildEvaluator(logger)
	if err != nil {
		return err
	}
	identity := oidc.Config{Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, IdentityMode: c.OIDC.IdentityMode, UserIDClaim: c.OIDC.UserIDClaim, TLSConfig: tlsCfg}
	discovery := wire.AuthConfig{Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, ClientSecret: c.OIDC.ClientSecret}
	caInstance, err := ca.New(sshcert.RawPrivateKey(string(privKey)), evaluator, ca.WithLogger(logger), ca.WithFacts(c.Directory, c.Inventory, identity, discovery, tlsCfg))
	if err != nil {
		return fmt.Errorf("unable to create CA: %w", err)
	}

	// Set up HTTP router. net/http.Server already recovers handler panics
	// per-request (see listenAndServe), so no Recoverer middleware is needed;
	// request logging goes through slog at the call sites that matter
	// (certificate issuance, discovery failures) rather than an access log
	// for every hit.
	r := http.NewServeMux()

	// Create certificate logger for audit trail.
	// Audit logs always emit at Info regardless of global verbosity.
	certLogger := caserver.NewSlogCertLogger(certAuditLogger(logger))

	server := caserver.New(caInstance, logger, certLogger)
	if err := validatePublicInventoryURL(c.ControlPublicURL, tlsCfg); err != nil {
		return err
	}
	server.PublicControlURL = c.ControlPublicURL
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

func validatePublicInventoryURL(value string, cfg tlsconfig.Config) error {
	if value == "" {
		return nil
	}
	// The URL is emitted inside Link's angle brackets. Delimiters and line
	// breaks must not be inserted literally into that header value.
	if strings.ContainsAny(value, "<>\r\n\"") {
		return fmt.Errorf("control-public-url must percent-encode Link header delimiters and cannot contain line breaks")
	}
	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("invalid control-public-url: %w", err)
	}
	if u.User != nil {
		return fmt.Errorf("control-public-url cannot contain embedded credentials; inventory authenticates requests separately")
	}
	if u.Fragment != "" {
		return fmt.Errorf("control-public-url cannot contain a fragment; fragments are not sent to the HTTP endpoint")
	}
	if u.IsAbs() {
		if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("control-public-url must be an HTTP(S) endpoint or a relative URL")
		}
		return cfg.ValidateURL(value)
	}
	return nil
}
