package facts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// DataClient supplies validated authorization  It exposes only lookups;
// caller identity and management operations belong to ControlClient.
type DataClient struct{ directory, inventory *transport }

// NewDataClient configures the directory and inventory lookup endpoints in use.
// Empty endpoints are omitted; at least one is required. Each endpoint is signed
// for its own service audience using the configured reader key.
func NewDataClient(directoryURL, inventoryURL string, key sshcert.RawPrivateKey, cfg tlsconfig.Config) (*DataClient, error) {
	if directoryURL == "" && inventoryURL == "" {
		return nil, fmt.Errorf("a fact lookup endpoint is required")
	}
	c := &DataClient{}
	var err error
	if directoryURL != "" {
		c.directory, err = newTransport(directoryURL, key, DirectoryAudience, cfg)
		if err != nil {
			return nil, err
		}
	}
	if inventoryURL != "" {
		c.inventory, err = newTransport(inventoryURL, key, InventoryAudience, cfg)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func lookup(ctx context.Context, service *transport, param, value string, result any) (bool, error) {
	resp, err := service.request(ctx, "GET", "/lookup", url.Values{param: {value}}, nil, "", wire.MaxBodySize)
	if err != nil {
		return false, err
	}
	if resp.status == http.StatusNotFound {
		return false, nil
	}
	if resp.status != http.StatusOK {
		return false, &ServiceError{Status: resp.status, Message: "fact lookup returned HTTP " + fmt.Sprint(resp.status) + ": " + strings.TrimSpace(string(resp.body))}
	}
	if err = json.Unmarshal(resp.body, result); err != nil {
		return false, fmt.Errorf("invalid fact response: %w", err)
	}
	return true, nil
}

// User returns active user facts for the exact authentication subject, or nil
// when absent or inactive. It validates identity and group names on every read.
func (c *DataClient) User(ctx context.Context, id string) (*User, error) {
	var u User
	found, err := lookup(ctx, c.directory, "id", id, &u)
	if err != nil || !found {
		return nil, err
	}
	if u.ID == "" || u.ID != id {
		return nil, fmt.Errorf("directory user does not match requested id")
	}
	for _, g := range u.Groups {
		if g == "" {
			return nil, fmt.Errorf("empty group ID")
		}
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
