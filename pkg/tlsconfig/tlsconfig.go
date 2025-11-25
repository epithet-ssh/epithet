// Package tlsconfig provides shared TLS configuration for HTTP clients.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config holds TLS configuration options for HTTP clients.
type Config struct {
	// Insecure disables TLS certificate verification.
	// NOT RECOMMENDED FOR PRODUCTION USE.
	Insecure bool

	// CACertFile is path to a PEM file containing trusted CA certificates.
	// If empty, system CA certificates are used.
	CACertFile string
}

// DefaultTimeout is the default timeout for HTTP clients.
const DefaultTimeout = 30 * time.Second

// NewHTTPClient creates an http.Client with the specified TLS configuration
// and the default timeout of 30 seconds.
func NewHTTPClient(cfg Config) (*http.Client, error) {
	return NewHTTPClientWithTimeout(cfg, DefaultTimeout)
}

// NewHTTPClientWithTimeout creates an http.Client with the specified TLS
// configuration and timeout.
func NewHTTPClientWithTimeout(cfg Config, timeout time.Duration) (*http.Client, error) {
	tlsCfg := &tls.Config{}

	if cfg.Insecure {
		tlsCfg.InsecureSkipVerify = true
	}

	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file %q: %w", cfg.CACertFile, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate file %q: no valid certificates found", cfg.CACertFile)
		}

		tlsCfg.RootCAs = caCertPool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// ValidateURL checks if a URL is allowed given this TLS configuration.
// Returns an error if the URL uses http:// without insecure mode enabled.
func (c Config) ValidateURL(url string) error {
	if strings.HasPrefix(url, "http://") && !c.Insecure {
		return fmt.Errorf("URL %q uses insecure http:// protocol; use https:// or pass --insecure flag to allow insecure connections", url)
	}
	return nil
}
