package caclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/breakerpool"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/gregjones/httpcache"
	gobreaker "github.com/sony/gobreaker/v2"
)

// InvalidTokenError indicates the authentication token is invalid or expired.
// The broker should clear the token and re-authenticate.
type InvalidTokenError struct {
	Message string
}

func (e *InvalidTokenError) Error() string {
	return fmt.Sprintf("invalid or expired token: %s", e.Message)
}

// PolicyDeniedError indicates authentication succeeded but policy denied access.
// The token is valid, but the user is not authorized for this connection.
type PolicyDeniedError struct {
	Message string
}

func (e *PolicyDeniedError) Error() string {
	return fmt.Sprintf("access denied by policy: %s", e.Message)
}

// CAUnavailableError indicates the CA service is temporarily unavailable.
// This is typically a transient infrastructure issue.
type CAUnavailableError struct {
	Message string
}

func (e *CAUnavailableError) Error() string {
	return fmt.Sprintf("CA unavailable: %s", e.Message)
}

// InvalidRequestError indicates the certificate request was malformed.
// This typically indicates a bug in the client code.
type InvalidRequestError struct {
	Message string
}

func (e *InvalidRequestError) Error() string {
	return fmt.Sprintf("invalid request: %s", e.Message)
}

// AllCAsUnavailableError indicates all configured CAs are unavailable.
// This happens when all CAs have their circuit breakers in the open state.
type AllCAsUnavailableError struct {
	Message string
}

func (e *AllCAsUnavailableError) Error() string {
	return fmt.Sprintf("all CAs unavailable: %s", e.Message)
}

// ConnectionNotHandledError indicates the CA/policy server does not handle this connection.
// The broker should fail the match and let SSH fall through to other auth methods.
type ConnectionNotHandledError struct {
	Message string
}

func (e *ConnectionNotHandledError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("connection not handled: %s", e.Message)
	}
	return "connection not handled by CA"
}

// Discovery contains information from the discovery endpoint.
type Discovery struct {
	MatchPatterns []string `json:"matchPatterns"`
}

// CertResponse contains a certificate and discovery information.
type CertResponse struct {
	Certificate  sshcert.RawCertificate
	Policy       policy.Policy
	DiscoveryURL string
}

// DefaultTimeout is the default per-request timeout for CA requests.
const DefaultTimeout = 15 * time.Second

// DefaultCooldown is the default circuit breaker cooldown duration.
const DefaultCooldown = 10 * time.Minute

// Client is a CA Client with support for multiple CA endpoints and failover.
type Client struct {
	httpClient      *http.Client
	discoveryClient *http.Client // Uses HTTP caching for discovery responses
	endpoints       []CAEndpoint
	pool            *breakerpool.Pool[*CertResponse, string]
	timeout         time.Duration
	cooldown        time.Duration
	logger          *slog.Logger

	// Cached discovery URL from Link header. Protected by discoveryMu.
	// Allows GetDiscovery() to skip hello request when URL is already known.
	discoveryMu  sync.RWMutex
	discoveryURL string
}

// New creates a new CA Client with the given endpoints.
// At least one endpoint is required.
func New(endpoints []CAEndpoint, options ...Option) (*Client, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("at least one CA endpoint is required")
	}

	// Create a cached transport for discovery requests
	// This uses in-memory caching with RFC 7234 compliance
	cachedTransport := httpcache.NewMemoryCacheTransport()

	client := &Client{
		endpoints: endpoints,
		timeout:   DefaultTimeout,
		cooldown:  DefaultCooldown,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		discoveryClient: &http.Client{
			Transport: cachedTransport,
			Timeout:   DefaultTimeout,
		},
	}

	for _, o := range options {
		if err := o.apply(client); err != nil {
			return nil, err
		}
	}

	// Create entries for the breakerpool
	entries := make([]breakerpool.Entry[string], len(endpoints))
	for i, ep := range endpoints {
		entries[i] = breakerpool.Entry[string]{
			State:    ep.URL,
			Priority: ep.Priority,
		}
	}

	// Default circuit breaker settings
	defaults := gobreaker.Settings{
		Timeout: client.cooldown,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 1
		},
		IsSuccessful: isSuccessfulForCircuitBreaker,
	}

	client.pool = breakerpool.New[*CertResponse](entries, defaults)

	return client, nil
}

// Option configures the agent
type Option interface {
	apply(*Client) error
}

type optionFunc func(*Client) error

func (f optionFunc) apply(a *Client) error {
	return f(a)
}

// WithHTTPClient specifies the http client to use
func WithHTTPClient(httpClient *http.Client) Option {
	return optionFunc(func(c *Client) error {
		c.httpClient = httpClient
		return nil
	})
}

// WithLogger specifies the logger to use
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *Client) error {
		c.logger = logger
		return nil
	})
}

// WithTLSConfig creates an HTTP client with the specified TLS configuration
func WithTLSConfig(cfg tlsconfig.Config) Option {
	return optionFunc(func(c *Client) error {
		httpClient, err := tlsconfig.NewHTTPClientWithTimeout(cfg, c.timeout)
		if err != nil {
			return fmt.Errorf("failed to create HTTP client: %w", err)
		}
		c.httpClient = httpClient
		return nil
	})
}

// WithTimeout sets the per-request timeout for CA requests.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *Client) error {
		c.timeout = d
		c.httpClient.Timeout = d
		return nil
	})
}

// WithCooldown sets the circuit breaker cooldown duration.
// Failed CAs will be unavailable for this duration before being retried.
func WithCooldown(d time.Duration) Option {
	return optionFunc(func(c *Client) error {
		c.cooldown = d
		return nil
	})
}

// GetCert requests a certificate from the CA, with automatic failover to backup CAs.
// It tries CAs in priority order, using circuit breakers to skip temporarily unavailable CAs.
// The token is sent in the Authorization header, not in the request body.
// Returns CertResponse containing the certificate, policy, and discovery URL.
func (c *Client) GetCert(ctx context.Context, token string, req *caserver.CreateCertRequest) (*CertResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	result, err := c.pool.Execute(func(caURL string) (*CertResponse, error) {
		if c.logger != nil {
			c.logger.Debug("trying CA", "url", caURL)
		}
		return c.doRequest(ctx, caURL, token, body)
	})

	if err != nil {
		// Convert breakerpool.AllUnavailableError to our AllCAsUnavailableError
		var allUnavail *breakerpool.AllUnavailableError
		if errors.As(err, &allUnavail) {
			return nil, &AllCAsUnavailableError{
				Message: allUnavail.Error(),
			}
		}
		return nil, err
	}

	return result, nil
}

// GetDiscovery fetches discovery data using the cached discovery URL.
// If no URL is cached (from a previous cert request), returns nil.
// The discovery response itself is cached via httpcache.
func (c *Client) GetDiscovery(ctx context.Context, token string) (*Discovery, error) {
	c.discoveryMu.RLock()
	url := c.discoveryURL
	c.discoveryMu.RUnlock()

	if url == "" {
		// No cached URL - discovery not available yet
		// URL will be learned from the next cert request's Link header
		return nil, nil
	}

	if c.logger != nil {
		c.logger.Debug("fetching discovery from cached URL", "url", url)
	}

	return c.fetchDiscovery(ctx, url, token)
}

// Hello validates a token with the CA and learns the discovery URL.
// This sends an empty body to the CA's hello endpoint, which validates the token
// with the policy server and returns the discovery URL in the Link header.
// Returns nil on success. The discovery URL is cached for subsequent GetDiscovery calls.
func (c *Client) Hello(ctx context.Context, token string) error {
	// Hello sends an empty JSON object - the CA routes based on body shape
	body := []byte("{}")

	// Try each endpoint in order (Hello is infrequent, doesn't need full pool machinery)
	var lastErr error
	for _, ep := range c.endpoints {
		if c.logger != nil {
			c.logger.Debug("Hello request", "url", ep.URL)
		}
		err := c.doHello(ctx, ep.URL, token, body)
		if err == nil {
			return nil
		}
		lastErr = err
		// Don't failover on auth errors - they'll fail on all CAs
		var invalidToken *InvalidTokenError
		var policyDenied *PolicyDeniedError
		if errors.As(err, &invalidToken) || errors.As(err, &policyDenied) {
			return err
		}
		// Try next endpoint for infrastructure errors
		if c.logger != nil {
			c.logger.Debug("Hello failed, trying next endpoint", "url", ep.URL, "error", err)
		}
	}
	return lastErr
}

// doHello makes a single hello request to a CA.
func (c *Client) doHello(ctx context.Context, caURL string, token string, body []byte) error {
	if c.logger != nil {
		c.logger.Debug("http request", "method", "POST", "url", caURL, "body_size", len(body))
	}

	rq, err := http.NewRequest("POST", caURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)

	start := time.Now()
	res, err := c.httpClient.Do(rq.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "POST", "url", caURL, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return err
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if c.logger != nil {
		c.logger.Debug("http response", "method", "POST", "url", caURL, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	if res.StatusCode != http.StatusOK {
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return &InvalidTokenError{Message: string(respBody)}
		case http.StatusForbidden:
			return &PolicyDeniedError{Message: string(respBody)}
		default:
			if res.StatusCode >= 500 {
				return &CAUnavailableError{Message: string(respBody)}
			}
			return &InvalidRequestError{Message: string(respBody)}
		}
	}

	// Extract and cache discovery URL from Link header
	discoveryURL := parseLinkHeader(res.Header.Get("Link"), "discovery")
	if discoveryURL != "" {
		c.discoveryMu.Lock()
		c.discoveryURL = discoveryURL
		c.discoveryMu.Unlock()
		if c.logger != nil {
			c.logger.Debug("cached discovery URL from Hello", "url", discoveryURL)
		}
	}

	return nil
}

// SetDiscoveryURL sets the cached discovery URL. This is primarily for testing.
// In normal operation, the URL is learned from CA cert response Link headers.
func (c *Client) SetDiscoveryURL(url string) {
	c.discoveryMu.Lock()
	c.discoveryURL = url
	c.discoveryMu.Unlock()
}

// fetchDiscovery fetches discovery data from the given URL.
// Uses the cached HTTP client for RFC 7234 compliant caching.
func (c *Client) fetchDiscovery(ctx context.Context, url string, token string) (*Discovery, error) {
	if c.logger != nil {
		c.logger.Debug("http request", "method", "GET", "url", url)
	}

	rq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	rq.Header.Set("Authorization", "Bearer "+token)

	// Use the cached client for discovery requests
	start := time.Now()
	res, err := c.discoveryClient.Do(rq.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "GET", "url", url, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return nil, err
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if c.logger != nil {
		c.logger.Debug("http response", "method", "GET", "url", url, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	if res.StatusCode != http.StatusOK {
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, &InvalidTokenError{Message: string(respBody)}
		case http.StatusForbidden:
			return nil, &PolicyDeniedError{Message: string(respBody)}
		default:
			if res.StatusCode >= 500 {
				return nil, &CAUnavailableError{Message: string(respBody)}
			}
			return nil, &InvalidRequestError{Message: string(respBody)}
		}
	}

	var discovery Discovery
	if err := json.Unmarshal(respBody, &discovery); err != nil {
		return nil, fmt.Errorf("failed to unmarshal discovery response: %w", err)
	}

	return &discovery, nil
}

// doRequest makes a single HTTP request to a CA and returns the response with discovery URL.
func (c *Client) doRequest(ctx context.Context, caURL string, token string, body []byte) (*CertResponse, error) {
	if c.logger != nil {
		c.logger.Debug("http request", "method", "POST", "url", caURL, "body_size", len(body))
	}

	rq, err := http.NewRequest("POST", caURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)

	start := time.Now()
	res, err := c.httpClient.Do(rq.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "POST", "url", caURL, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return nil, err
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if c.logger != nil {
		c.logger.Debug("http response", "method", "POST", "url", caURL, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	if res.StatusCode != 200 {
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, &InvalidTokenError{Message: string(respBody)}
		case http.StatusForbidden:
			return nil, &PolicyDeniedError{Message: string(respBody)}
		case http.StatusUnprocessableEntity:
			return nil, &ConnectionNotHandledError{Message: string(respBody)}
		default:
			if res.StatusCode >= 500 {
				return nil, &CAUnavailableError{Message: string(respBody)}
			}
			return nil, &InvalidRequestError{Message: string(respBody)}
		}
	}

	var caResp caserver.CreateCertResponse
	err = json.Unmarshal(respBody, &caResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CA response (body=%s): %w", string(respBody), err)
	}

	// Extract and cache discovery URL from Link header
	discoveryURL := parseLinkHeader(res.Header.Get("Link"), "discovery")
	if discoveryURL != "" {
		c.discoveryMu.Lock()
		c.discoveryURL = discoveryURL
		c.discoveryMu.Unlock()
	}

	return &CertResponse{
		Certificate:  caResp.Certificate,
		Policy:       caResp.Policy,
		DiscoveryURL: discoveryURL,
	}, nil
}

// isSuccessfulForCircuitBreaker determines whether an error should count as a
// circuit breaker failure. Only infrastructure errors (connection failures,
// timeouts, 5xx) trigger the circuit breaker. Auth and policy errors do not.
func isSuccessfulForCircuitBreaker(err error) bool {
	if err == nil {
		return true
	}

	// CAUnavailableError (5xx) triggers circuit breaker
	var caUnavail *CAUnavailableError
	if errors.As(err, &caUnavail) {
		return false
	}

	// InvalidTokenError (401) - auth issue, not infrastructure
	var invalidToken *InvalidTokenError
	if errors.As(err, &invalidToken) {
		return true // Don't trip breaker
	}

	// PolicyDeniedError (403) - policy issue, not infrastructure
	var policyDenied *PolicyDeniedError
	if errors.As(err, &policyDenied) {
		return true // Don't trip breaker
	}

	// InvalidRequestError (4xx) - client issue, not infrastructure
	var invalidReq *InvalidRequestError
	if errors.As(err, &invalidReq) {
		return true // Don't trip breaker
	}

	// ConnectionNotHandledError (422) - routing issue, not infrastructure
	var connNotHandled *ConnectionNotHandledError
	if errors.As(err, &connNotHandled) {
		return true // Don't trip breaker
	}

	// Unknown errors - treat as infrastructure failures to be safe
	// This includes connection refused, DNS failures, TLS errors, etc.
	return false
}

// parseLinkHeader extracts the URL for a given rel from a Link header.
// Link header format: <url>; rel="name"
// Returns empty string if not found or malformed.
func parseLinkHeader(header, rel string) string {
	if header == "" {
		return ""
	}

	// Parse Link header: <url>; rel="..."
	start := strings.Index(header, "<")
	end := strings.Index(header, ">")
	if start == -1 || end == -1 || end <= start {
		return ""
	}

	url := header[start+1 : end]

	// Check for the rel parameter
	relParam := `rel="` + rel + `"`
	if !strings.Contains(header, relParam) {
		return ""
	}

	return url
}
