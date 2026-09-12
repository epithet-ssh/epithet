package caclient

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

// InventoryURL follows only the configured CA's explicit inventory relation.
// Unlike auth discovery, inventory may intentionally be on another HTTPS origin.
// No credentials are sent during discovery, or forwarded through redirects.
func InventoryURL(root *RootResponse, cfg tlsconfig.Config) (string, error) {
	headers := http.Header{}
	headers["Link"] = root.Links
	ref, ok := findLinkTarget(headers, inventoryapi.InventoryRelation)
	if !ok {
		return "", nil
	}
	base, err := url.Parse(root.FinalURL)
	if err != nil {
		return "", err
	}
	target, err := resolveLinkTarget(base, ref)
	if err != nil {
		return "", err
	}
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" || target.Host == "" || (target.Scheme != "https" && target.Scheme != "http") {
		return "", fmt.Errorf("invalid advertised inventory URL")
	}
	if err = cfg.ValidateURL(target.String()); err != nil {
		return "", err
	}
	return target.String(), nil
}

const MaxControlResponse = 8 << 20

// DoInventory sends a single operation to a complete advertised URL. Callers
// choose the credential for this operation; redirects never receive it.
func DoInventory(ctx context.Context, client *http.Client, endpoint, bearer string, request inventoryapi.ControlRequest) (*inventoryapi.ControlResponse, int, error) {
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
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(req)
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

// InventoryWithToken discovers through this agent's CA configuration. The
// client cannot nominate a destination to which the agent should send its token.
func (c *Client) InventoryWithToken(ctx context.Context, token string, request inventoryapi.ControlRequest) (*inventoryapi.ControlResponse, int, error) {
	root, err := c.GetRoot(ctx)
	if err != nil {
		return nil, 0, err
	}
	endpoint, err := InventoryURL(root, c.tlsConfig)
	if err != nil {
		return nil, 0, err
	}
	if endpoint == "" {
		return nil, 0, fmt.Errorf("CA does not advertise managed inventory")
	}
	response, status, err := DoInventory(ctx, c.httpClient, endpoint, token, request)
	if response != nil && response.Secret != "" {
		response.CAURL = root.FinalURL
	}
	return response, status, err
}
