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
	"time"

	"github.com/epithet-ssh/epithet/pkg/breakerpool"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
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

// DefaultTimeout is the default per-request timeout for CA requests.
const DefaultTimeout = 15 * time.Second

// DefaultCooldown is the default circuit breaker cooldown duration.
const DefaultCooldown = 10 * time.Minute

// Client is a CA Client with support for multiple CA endpoints and failover.
type Client struct {
	httpClient *http.Client
	endpoints  []CAEndpoint
	pool       *breakerpool.Pool[*caserver.CreateCertResponse, string]
	timeout    time.Duration
	cooldown   time.Duration
	logger     *slog.Logger
}

// New creates a new CA Client with the given endpoints.
// At least one endpoint is required.
func New(endpoints []CAEndpoint, options ...Option) (*Client, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("at least one CA endpoint is required")
	}

	client := &Client{
		endpoints: endpoints,
		timeout:   DefaultTimeout,
		cooldown:  DefaultCooldown,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
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

	client.pool = breakerpool.New[*caserver.CreateCertResponse](entries, defaults)

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
func (c *Client) GetCert(ctx context.Context, token string, req *caserver.CreateCertRequest) (*caserver.CreateCertResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	result, err := c.pool.Execute(func(caURL string) (*caserver.CreateCertResponse, error) {
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

// Hello validates a token with the CA server.
// Sends empty body {} with Authorization: Bearer header.
// Returns nil on success, or appropriate error (InvalidTokenError, PolicyDeniedError, etc.)
// Tries endpoints in priority order until one succeeds or all fail.
func (c *Client) Hello(ctx context.Context, token string) error {
	body := []byte("{}")

	var lastErr error
	for _, ep := range c.endpoints {
		if c.logger != nil {
			c.logger.Debug("hello request to CA", "url", ep.URL)
		}
		err := c.doHelloRequest(ctx, ep.URL, token, body)
		if err == nil {
			return nil
		}

		// Check if this is an infrastructure error (should try next CA)
		var caUnavail *CAUnavailableError
		if errors.As(err, &caUnavail) {
			lastErr = err
			continue
		}

		// Auth/policy errors - return immediately, don't try other CAs
		return err
	}

	if lastErr != nil {
		return &AllCAsUnavailableError{Message: lastErr.Error()}
	}
	return &AllCAsUnavailableError{Message: "no CA endpoints configured"}
}

// doHelloRequest makes a hello request to validate a token.
func (c *Client) doHelloRequest(ctx context.Context, caURL string, token string, body []byte) error {
	rq, err := http.NewRequest("POST", caURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)

	res, err := c.httpClient.Do(rq.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if c.logger != nil {
		c.logger.Debug("CA hello response", "url", caURL, "status", res.StatusCode)
	}

	if res.StatusCode != http.StatusOK {
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return &InvalidTokenError{Message: string(respBody)}
		case http.StatusForbidden:
			return &PolicyDeniedError{Message: string(respBody)}
		case http.StatusUnprocessableEntity:
			return &ConnectionNotHandledError{Message: string(respBody)}
		default:
			if res.StatusCode >= 500 {
				return &CAUnavailableError{Message: string(respBody)}
			}
			return &InvalidRequestError{Message: string(respBody)}
		}
	}

	return nil
}

// doRequest makes a single HTTP request to a CA.
func (c *Client) doRequest(ctx context.Context, caURL string, token string, body []byte) (*caserver.CreateCertResponse, error) {
	if c.logger != nil {
		c.logger.Debug("CA request", "url", caURL, "body", string(body))
	}

	rq, err := http.NewRequest("POST", caURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+token)

	res, err := c.httpClient.Do(rq.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if c.logger != nil {
		c.logger.Debug("CA response", "url", caURL, "status", res.StatusCode, "body", string(respBody))
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

	resp := caserver.CreateCertResponse{}
	err = json.Unmarshal(respBody, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CA response (body=%s): %w", string(respBody), err)
	}

	return &resp, nil
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
