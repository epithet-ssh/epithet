package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"golang.org/x/crypto/ssh"
)

// CA performs CA operations.
type CA struct {
	signer     ssh.Signer
	privateKey sshcert.RawPrivateKey
	policyURL  string
	httpClient *http.Client
	logger     *slog.Logger

	// svcSigner mints the request-bound JWT sent to the policy server.
	svcSigner *serviceauth.Signer
}

// PolicyURL returns the URL of the policy server.
func (c *CA) PolicyURL() string {
	return c.policyURL
}

// New creates a new CA.
func New(privateKey sshcert.RawPrivateKey, policyURL string, options ...Option) (*CA, error) {
	sshSigner, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	svcSigner, err := serviceauth.NewSigner(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create service auth signer: %w", err)
	}

	ca := &CA{
		signer:     sshSigner,
		privateKey: privateKey,
		policyURL:  policyURL,
		svcSigner:  svcSigner,
	}

	for _, o := range options {
		if err := o.apply(ca); err != nil {
			return nil, err
		}
	}

	if ca.httpClient == nil {
		ca.httpClient = &http.Client{
			Timeout: tlsconfig.DefaultTimeout,
		}
	}

	// When the policy URL is a unix socket, configure the HTTP transport to
	// dial the socket and rewrite the URL to http://localhost.
	if socketPath, ok := strings.CutPrefix(ca.policyURL, "unix://"); ok {
		dialFunc := func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}
		ca.httpClient.Transport = &http.Transport{DialContext: dialFunc}

		ca.policyURL = "http://localhost/"
	}

	return ca, nil
}

// Option configures the CA.
type Option interface {
	apply(*CA) error
}

type optionFunc func(*CA) error

func (f optionFunc) apply(a *CA) error {
	return f(a)
}

// WithTLSConfig creates an HTTP client with the specified TLS configuration,
// using tlsconfig's shared default timeout rather than a locally-duplicated
// literal.
func WithTLSConfig(cfg tlsconfig.Config) Option {
	return optionFunc(func(c *CA) error {
		httpClient, err := tlsconfig.NewHTTPClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to create HTTP client: %w", err)
		}
		c.httpClient = httpClient
		return nil
	})
}

// WithLogger configures the CA to use the specified logger.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *CA) error {
		c.logger = logger
		return nil
	})
}

// PublicKey returns the ssh on-disk format public key for the CA.
func (c *CA) PublicKey() sshcert.RawPublicKey {
	pk := c.signer.PublicKey()
	return sshcert.RawPublicKey(string(ssh.MarshalAuthorizedKey(pk)))
}

// FetchDiscovery fetches discovery data from the policy server.
// The request carries a CA-minted, request-bound JWT (pkg/serviceauth). The
// response's Cache-Control header is preserved on the returned Discovery so
// callers (the CA server's /discovery handler) can pass it through to
// clients; this CA client itself does not cache.
func (c *CA) FetchDiscovery(ctx context.Context) (*wire.Discovery, error) {
	req, err := http.NewRequest("GET", c.policyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// GET has no body, so the token's bh claim covers the empty string.
	if err := c.svcSigner.Authorize(req, nil); err != nil {
		return nil, fmt.Errorf("error signing request: %w", err)
	}

	if c.logger != nil {
		c.logger.Debug("http request", "method", "GET", "url", c.policyURL, "purpose", "discovery")
	}

	start := time.Now()
	res, err := c.httpClient.Do(req.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "GET", "url", c.policyURL, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return nil, fmt.Errorf("error fetching discovery: %w", err)
	}
	defer res.Body.Close()

	if c.logger != nil {
		c.logger.Debug("http response", "method", "GET", "url", c.policyURL, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	buf, err := io.ReadAll(io.LimitReader(res.Body, wire.MaxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("error reading discovery response: %w", err)
	}

	// Check if policy server response exceeds the limit.
	if len(buf) > wire.MaxBodySize {
		return nil, fmt.Errorf("policy server response exceeds %d bytes", wire.MaxBodySize)
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("policy server returned %d for discovery: %s", res.StatusCode, string(buf))
	}

	var discovery wire.Discovery
	if err := json.Unmarshal(buf, &discovery); err != nil {
		return nil, fmt.Errorf("error parsing discovery response: %w", err)
	}

	// Preserve Cache-Control from the policy server for passthrough to clients.
	discovery.CacheControl = res.Header.Get("Cache-Control")

	return &discovery, nil
}

// RequestPolicy requests policy from the policy server for a cert request.
// The request carries a CA-minted, request-bound JWT (pkg/serviceauth).
func (c *CA) RequestPolicy(ctx context.Context, token string, conn policy.Connection) (*wire.PolicyResponse, error) {
	body, err := json.Marshal(wire.PolicyRequest{Token: token, Connection: conn})
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %w", err)
	}

	if c.logger != nil {
		c.logger.Debug("http request", "method", "POST", "url", c.policyURL, "body_size", len(body))
	}

	req, err := http.NewRequest("POST", c.policyURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Add("Content-type", "application/json")

	if err := c.svcSigner.Authorize(req, body); err != nil {
		return nil, fmt.Errorf("error signing request: %w", err)
	}

	start := time.Now()
	res, err := c.httpClient.Do(req.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "POST", "url", c.policyURL, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return nil, fmt.Errorf("error executing request: %w", err)
	}
	defer res.Body.Close()

	if c.logger != nil {
		c.logger.Debug("http response", "method", "POST", "url", c.policyURL, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	buf, err := io.ReadAll(io.LimitReader(res.Body, wire.MaxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	// Check if policy server response exceeds the limit.
	if len(buf) > wire.MaxBodySize {
		return nil, fmt.Errorf("policy server response exceeds %d bytes", wire.MaxBodySize)
	}

	if res.StatusCode != 200 {
		return nil, &wire.PolicyError{
			StatusCode: res.StatusCode,
			Message:    string(buf),
		}
	}

	policyResp := &wire.PolicyResponse{}
	err = json.Unmarshal(buf, policyResp)
	if err != nil {
		return nil, fmt.Errorf("error parsing response from %s: %w", c.policyURL, err)
	}
	return policyResp, nil
}

// SignPublicKey signs a key to generate a certificate.
func (c *CA) SignPublicKey(rawPubKey sshcert.RawPublicKey, params *wire.CertParams) (sshcert.RawCertificate, error) {
	// A ceiling already in the past can never produce a usable certificate,
	// and signing one anyway would silently hand out a dead credential.
	if !params.NotAfter.IsZero() && params.NotAfter.Before(time.Now()) {
		return "", fmt.Errorf("certificate NotAfter %s is in the past", params.NotAfter)
	}

	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	serial := binary.LittleEndian.Uint64(buf)

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawPubKey))
	if err != nil {
		return "", err
	}

	// The certificate must never outlive the auth session that requested it,
	// so clamp its validity to NotAfter when that ceiling is tighter than
	// the requested Expiration.
	validBefore := time.Now().Add(params.Expiration)
	if !params.NotAfter.IsZero() && params.NotAfter.Before(validBefore) {
		validBefore = params.NotAfter
	}

	certificate := ssh.Certificate{
		Serial:          serial,
		Key:             pubKey,
		KeyId:           params.Identity,
		ValidPrincipals: params.Names,
		ValidAfter:      uint64(time.Now().Unix() - 60),
		ValidBefore:     uint64(validBefore.Unix()),
		CertType:        ssh.UserCert,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      params.Extensions,
		},
	}
	err = certificate.SignCert(rand.Reader, c.signer)
	if err != nil {
		return "", err
	}
	rawCert := ssh.MarshalAuthorizedKey(&certificate)
	if len(rawCert) == 0 {
		return "", errors.New("unknown problem marshaling certificate")
	}
	return sshcert.RawCertificate(string(rawCert)), nil
}
