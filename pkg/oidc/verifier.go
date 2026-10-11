package oidc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// ErrUnavailable distinguishes an unavailable authentication dependency from an
// invalid token during service startup. Signing-key verification errors retain
// their existing behavior; this class only represents pending discovery.
var ErrUnavailable = errors.New("OIDC dependency unavailable")

// Verifier checks ID tokens independently of directory identity mapping.
// It can be shared by concurrent callers and caches the provider's signing keys.
type Verifier struct {
	config   VerifierConfig
	client   *http.Client
	mu       sync.RWMutex
	verifier *coreoidc.IDTokenVerifier
}

// VerifierConfig identifies the issuer and audience trusted for ID tokens.
// Login credentials and directory identity mapping are independent of verification.
type VerifierConfig struct {
	IssuerURL string
	ClientID  string
	TLSConfig tlsconfig.Config
}

// NewVerifier discovers the configured issuer and prepares token verification.
func NewVerifier(ctx context.Context, config VerifierConfig) (*Verifier, error) {
	if config.IssuerURL == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	client, err := tlsconfig.NewHTTPClient(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	provider, err := coreoidc.NewProvider(coreoidc.ClientContext(ctx, client), config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for %s: %w", config.IssuerURL, err)
	}
	return &Verifier{verifier: provider.Verifier(&coreoidc.Config{ClientID: config.ClientID})}, nil
}

// prepareVerifier validates local configuration without contacting the issuer.
func prepareVerifier(config VerifierConfig) (*Verifier, error) {
	if config.IssuerURL == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if err := validateEndpoint(config.IssuerURL); err != nil {
		return nil, fmt.Errorf("invalid OIDC issuer: %w", err)
	}
	client, err := tlsconfig.NewHTTPClient(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	return &Verifier{config: config, client: client}, nil
}

func validateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("expected an absolute HTTP(S) URL without credentials or fragment")
	}
	return nil
}

func (v *Verifier) discover(ctx context.Context) error {
	// The transport preserves discovery errors for retry classification. Signing
	// key requests retain the ordinary client and go-oidc verification behavior.
	discoveryClient := *v.client
	discoveryClient.Transport = discoveryTransport{base: v.client.Transport}
	provider, err := coreoidc.NewProvider(coreoidc.ClientContext(ctx, &discoveryClient), v.config.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider for %s: %w", v.config.IssuerURL, err)
	}
	verifier := provider.VerifierContext(coreoidc.ClientContext(context.Background(), v.client), &coreoidc.Config{ClientID: v.config.ClientID})
	v.mu.Lock()
	v.verifier = verifier
	v.mu.Unlock()
	return nil
}

// Ready reports whether discovery has completed, without probing the issuer.
func (v *Verifier) Ready() error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.verifier == nil {
		return fmt.Errorf("%w: OIDC discovery unavailable", ErrUnavailable)
	}
	return nil
}

// Run discovers the issuer until successful, cancelled, or a permanent failure.
// A service calls it once, alongside its HTTP listener. No request waits for it.
func (v *Verifier) Run(ctx context.Context, logger *slog.Logger) error {
	backoff := time.Second
	retrying := false
	for {
		err := v.discover(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			if retrying {
				logger.Warn("OIDC discovery recovered", "issuer", v.config.IssuerURL)
			} else {
				logger.Info("OIDC discovery ready", "issuer", v.config.IssuerURL)
			}
			return nil
		}
		if !retryDiscovery(err) {
			return err
		}
		retrying = true
		delay := backoff/2 + time.Duration(rand.Int64N(int64(backoff/2)+1))
		logger.Warn("OIDC discovery unavailable; retrying", "issuer", v.config.IssuerURL, "error", err, "retry_in", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func retryDiscovery(err error) bool {
	var status *discoveryStatusError
	if errors.As(err, &status) {
		return status.code == 429 || (status.code >= 500 && status.code < 600)
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return false
	}
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	if errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return dns.IsTemporary || dns.IsTimeout
	}
	var network net.Error
	return (errors.As(err, &network) && (network.Timeout() || network.Temporary())) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

type discoveryStatusError struct{ code int }

func (e *discoveryStatusError) Error() string {
	return fmt.Sprintf("OIDC endpoint returned HTTP %d", e.code)
}

// discoveryTransport preserves typed status/body errors that go-oidc otherwise
// formats as text. It is used only for startup discovery, never signing keys.
type discoveryTransport struct {
	base http.RoundTripper
}

func (t discoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil {
		// Leave redirect handling to the HTTP client's existing policy.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return resp, nil
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			err = &discoveryStatusError{code: resp.StatusCode}
		} else {
			var body []byte
			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Verify checks signature, issuer, audience, expiry, and a nonempty subject.
// Callers may inspect claims only after this succeeds.
func (v *Verifier) Verify(ctx context.Context, token string) (*coreoidc.IDToken, error) {
	v.mu.RLock()
	verifier := v.verifier
	v.mu.RUnlock()
	if verifier == nil {
		return nil, fmt.Errorf("%w: OIDC discovery unavailable", ErrUnavailable)
	}
	verified, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	if verified.Subject == "" {
		return nil, fmt.Errorf("OIDC token has no subject")
	}
	return verified, nil
}
