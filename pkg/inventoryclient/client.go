// Package inventoryclient implements public inventory management requests.
package inventoryclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

const MaxControlResponse = 8 << 20

// Client sends inventory RPCs over its own configured transport.
type Client struct {
	httpClient *http.Client
	endpoint   string
}

// New binds a client to the complete public inventory URL.
// An empty endpoint means the CA does not advertise managed inventory.
func New(endpoint string, cfg tlsconfig.Config) (*Client, error) {
	if endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid inventory URL")
		}
		if err := cfg.ValidateURL(endpoint); err != nil {
			return nil, err
		}
	}
	client, err := tlsconfig.NewHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{httpClient: client, endpoint: endpoint}, nil
}

// Control sends a single operation to the configured endpoint. Callers
// choose the credential for this operation; redirects never receive it.
func (c *Client) Control(ctx context.Context, bearer string, request inventoryapi.ControlRequest) (*inventoryapi.ControlResponse, int, error) {
	if c.endpoint == "" {
		return nil, 0, fmt.Errorf("CA does not advertise managed inventory")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxControlResponse+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(body) > MaxControlResponse {
		return nil, response.StatusCode, fmt.Errorf("inventory response exceeds size limit")
	}
	var result inventoryapi.ControlResponse
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, response.StatusCode, fmt.Errorf("invalid inventory response (HTTP %d)", response.StatusCode)
	}
	if response.StatusCode != 200 && response.StatusCode != 202 {
		return &result, response.StatusCode, fmt.Errorf("inventory: %s (HTTP %d)", strings.TrimSpace(result.Error), response.StatusCode)
	}
	return &result, response.StatusCode, nil
}
