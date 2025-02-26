package caclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"io"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/caserver"
)

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
func (c *Client) GetCert(ctx context.Context, req *caserver.CreateCertRequest) (*caserver.CreateCertResponse, ca.Status, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, ca.StatusError, err
	}

	rq, err := http.NewRequest("POST", c.caURL, bytes.NewReader(body))
	if err != nil {
		return nil, ca.StatusError, err
	}

	res, err := c.httpClient.Do(rq.WithContext(ctx))
	if err != nil {
		return nil, ca.StatusError, err
	}

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, ca.StatusError, err
	}

	status := ca.Status(res.StatusCode)

	switch status {
	case ca.StatusOk:
		resp := caserver.CreateCertResponse{}
		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, ca.StatusError, err
		}

		return &resp, ca.StatusOk, nil
	case ca.StatusNeedToken:
		return nil, status, nil
	case ca.StatusNotAllowed:
		return nil, status, nil
	case ca.StatusError:
		return nil, status, errors.New(string(body))
	default:
		return nil, status, fmt.Errorf("unexpected status from server: %d", res.StatusCode)
	}
}
