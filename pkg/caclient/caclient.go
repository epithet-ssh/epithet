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

	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
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

// DefaultTimeout is the default per-request timeout for CA requests.
const DefaultTimeout = 15 * time.Second

// DefaultCooldown is the default circuit breaker cooldown duration.
const DefaultCooldown = 10 * time.Minute

// Client is a CA Client with support for multiple CA endpoints and failover.
type Client struct {
	httpClient *http.Client
	endpoints  []CAEndpoint
	selector   *selector
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

	// Create selector after options are applied (cooldown may have changed)
	client.selector = newSelector(endpoints, client.cooldown)

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
func (c *Client) GetCert(ctx context.Context, req *caserver.CreateCertRequest) (*caserver.CreateCertResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var lastErr error

	// Try CAs until we succeed or exhaust all options
	for {
		// Get next available CA
		caURL, breaker := c.selector.next()
		if caURL == "" || breaker == nil {
			// All CAs unavailable
			if lastErr != nil {
				return nil, &AllCAsUnavailableError{
					Message: fmt.Sprintf("all CAs in circuit breaker, last error: %v", lastErr),
				}
			}
			return nil, &AllCAsUnavailableError{Message: "all CAs in circuit breaker"}
		}

		// Execute request through circuit breaker
		resp, err := breaker.Execute(func() (struct{}, error) {
			return struct{}{}, nil // We handle the actual request below
		})
		_ = resp // unused, we just use the breaker for state management

		// Make the actual request
		result, err := c.doRequest(ctx, caURL, body)
		if err != nil {
			// Check if this is a non-failover error (auth/policy issues)
			var invalidToken *InvalidTokenError
			var policyDenied *PolicyDeniedError
			var invalidReq *InvalidRequestError
			if errors.As(err, &invalidToken) || errors.As(err, &policyDenied) || errors.As(err, &invalidReq) {
				// Don't failover on auth/policy errors - return immediately
				// The circuit breaker's IsSuccessful already treats these as "successful"
				// so the breaker won't trip
				return nil, err
			}

			// Infrastructure error - record failure and try next CA
			// Execute through breaker to record the failure
			_, _ = breaker.Execute(func() (struct{}, error) {
				return struct{}{}, err
			})

			lastErr = err
			if c.logger != nil {
				c.logger.Warn("CA request failed, trying next CA", "url", caURL, "error", err)
			}
			continue
		}

		// Success - the breaker will record this automatically on next Execute
		return result, nil
	}
}

// doRequest makes a single HTTP request to a CA.
func (c *Client) doRequest(ctx context.Context, caURL string, body []byte) (*caserver.CreateCertResponse, error) {
	if c.logger != nil {
		c.logger.Debug("CA request", "url", caURL, "body", string(body))
	}

	rq, err := http.NewRequest("POST", caURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	rq.Header.Set("Content-Type", "application/json")

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
