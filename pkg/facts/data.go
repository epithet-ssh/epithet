package facts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// DataClient supplies validated authorization facts. It exposes only lookups;
// caller identity and management operations belong to ControlClient.
type DataClient struct{ directory, inventory *servicehttp.Client }

// NewDataClient configures the directory and inventory lookup endpoints in use.
// URLs identify complete lookup endpoints (Unix sockets use /lookup).
// Empty endpoints are omitted; at least one is required. Each endpoint is signed
// for its own service audience using the configured reader key.
func NewDataClient(directoryURL, inventoryURL string, key sshcert.RawPrivateKey, cfg tlsconfig.Config) (*DataClient, error) {
	if directoryURL == "" && inventoryURL == "" {
		return nil, fmt.Errorf("a fact lookup endpoint is required")
	}
	c := &DataClient{}
	var err error
	if directoryURL != "" {
		c.directory, err = servicehttp.New(directoryURL, "/lookup", key, serviceauth.DirectoryAudience, cfg)
		if err != nil {
			return nil, err
		}
	}
	if inventoryURL != "" {
		c.inventory, err = servicehttp.New(inventoryURL, "/lookup", key, serviceauth.InventoryAudience, cfg)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func lookup(ctx context.Context, service *servicehttp.Client, param, value string, result any) (bool, error) {
	if service == nil {
		return false, &ServiceError{Status: 404, Message: "fact endpoint is not configured"}
	}
	target, _ := url.Parse(service.Endpoint())
	target.RawQuery = url.Values{param: {value}}.Encode()
	resp, err := service.Do(ctx, servicehttp.Request{Method: "GET", URL: target.String()}, wire.MaxBodySize)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if resp.Status == http.StatusNotFound {
		return false, nil
	}
	if resp.Status != http.StatusOK {
		return false, &ServiceError{Status: resp.Status, Message: "fact lookup returned HTTP " + fmt.Sprint(resp.Status) + ": " + strings.TrimSpace(string(resp.Body))}
	}
	if err = json.Unmarshal(resp.Body, result); err != nil {
		return false, fmt.Errorf("invalid fact response: %w", err)
	}
	return true, nil
}

// User returns active user facts for the exact authentication subject, or nil
// when absent or inactive. It validates identity and object attributes on every read.
func (c *DataClient) User(ctx context.Context, id string) (*User, error) {
	var u User
	found, err := lookup(ctx, c.directory, "id", id, &u)
	if err != nil || !found {
		return nil, err
	}
	if err := u.PolicyUser().Validate(id); err != nil {
		return nil, err
	}
	return &u, nil
}

// Host returns facts for a normalized hostname, or nil when absent. It validates
// the returned names, account restrictions and principal metadata before use.
func (c *DataClient) Host(ctx context.Context, name string) (*Host, error) {
	var h Host
	found, err := lookup(ctx, c.inventory, "host", name, &h)
	if err != nil || !found {
		return nil, err
	}
	if err = h.Host.Validate(name); err != nil {
		return nil, err
	}
	return &h, nil
}
