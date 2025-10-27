package caclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/caserver"
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

// Client is a CA Client
type Client struct {
	httpClient *http.Client
	caURL      string
}

// New creates a new CA Client
func New(url string, options ...Option) *Client {
	client := &Client{
		caURL: url,
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}

	for _, o := range options {
		o.apply(client)
	}

	return client
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

// GetCert converts a token to a cert
func (c *Client) GetCert(ctx context.Context, req *caserver.CreateCertRequest) (*caserver.CreateCertResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	rq, err := http.NewRequest("POST", c.caURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	res, err := c.httpClient.Do(rq.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		// Map HTTP status codes to domain-specific errors
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, &InvalidTokenError{Message: string(body)}
		case http.StatusForbidden:
			return nil, &PolicyDeniedError{Message: string(body)}
		default:
			if res.StatusCode >= 500 {
				return nil, &CAUnavailableError{Message: string(body)}
			}
			// Other 4xx errors
			return nil, &InvalidRequestError{Message: string(body)}
		}
	}

	resp := caserver.CreateCertResponse{}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}
