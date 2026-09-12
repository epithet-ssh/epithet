package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type CACLI struct {
	InventoryPublicURL string `help:"Client-accessible managed inventory URL advertised at bootstrap" name:"inventory-public-url"`
	InventoryProxy     bool   `help:"Expose managed inventory through this CA listener (combined server)" name:"inventory-proxy"`

	Inventory string `help:"URL for inventory service" name:"inventory" required:"true"`
	Policy    string `help:"URL for policy service" short:"p" env:"POLICY_URL" required:"true"`
	Key       string `help:"Path to ca private key" short:"k" default:"/etc/epithet/ca.key"`
	Listen    string `help:"Address to listen on" short:"l" env:"PORT" default:"0.0.0.0:8080"`
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
	caInstance, err := ca.New(sshcert.RawPrivateKey(string(privKey)), c.Policy, ca.WithTLSConfig(tlsCfg), ca.WithLogger(logger), ca.WithInventory(c.Inventory, tlsCfg))
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
	if c.InventoryPublicURL != "" {
		u, err := url.Parse(c.InventoryPublicURL)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(c.InventoryPublicURL, "<>\r\n\"") {
			return fmt.Errorf("invalid inventory-public-url")
		}
		if u.IsAbs() {
			if err := tlsCfg.ValidateURL(c.InventoryPublicURL); err != nil {
				return err
			}
			if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return fmt.Errorf("inventory-public-url must be HTTPS")
			}
		}
		server.SetInventoryURL(c.InventoryPublicURL)
	}
	if c.InventoryProxy {
		proxy, err := inventoryControlProxy(c.Inventory)
		if err != nil {
			return err
		}
		r.Handle("/inventory", proxy)
	}
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

// The combined listener exposes only the managed endpoint. It never proxies
// arbitrary resolver/policy paths or gives these requests service credentials.
func inventoryControlProxy(endpoint string) (http.Handler, error) {
	path, ok := strings.CutPrefix(endpoint, "unix://")
	if !ok || path == "" {
		return nil, fmt.Errorf("inventory proxy requires a private Unix socket")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	return &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		r.Out.URL.Scheme = "http"
		r.Out.URL.Host = "inventory"
		r.Out.URL.Path = "/manage"
		r.Out.URL.RawPath = ""
		r.Out.Host = "inventory"
	}}, nil
}
