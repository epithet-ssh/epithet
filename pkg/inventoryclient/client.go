// Package inventoryclient implements public inventory management requests.
package inventoryclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

const MaxControlResponse = 8 << 20

// Client sends inventory RPCs over its own configured transport.
type Client struct {
	httpClient *http.Client
	tlsConfig  tlsconfig.Config
}

func New(cfg tlsconfig.Config) (*Client, error) {
	client, err := tlsconfig.NewHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{httpClient: client, tlsConfig: cfg}, nil
}

// Control sends a single operation to a complete advertised URL. Callers
// choose the credential for this operation; redirects never receive it.
func (c *Client) Control(ctx context.Context, endpoint, bearer string, request inventoryapi.ControlRequest) (*inventoryapi.ControlResponse, int, error) {
	if err := c.tlsConfig.ValidateURL(endpoint); err != nil {
		return nil, 0, err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(data))
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
