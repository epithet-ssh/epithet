package caclient

import "net/http"

// Client is a CA Client
type Client struct {
	httpClient *http.Client
	caURL      string
}

// New creates a new CA Client
func New(url string, options ...Option) *Client {
	client := &Client{
		caURL:      url,
		httpClient: http.DefaultClient,
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

// ConvertToken converts a token to a cert
func (c *Client) ConvertToken(token string, pubkey string) (string, error) {
	return "", nil
}
