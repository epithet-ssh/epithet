// Package facts defines provider and administration protocols and their public clients.
// Provider dispatch and authorization belong to control; storage and HTTP adapters
// live in the directory, inventory and server subpackages.
package facts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
)

// DataClient supplies validated authorization facts. It exposes only lookups;
// caller identity and management operations belong to pkg/facts/control.
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
func (c *DataClient) Host(ctx context.Context, name string) (*wire.Host, error) {
	var h wire.Host
	found, err := lookup(ctx, c.inventory, "host", name, &h)
	if err != nil || !found {
		return nil, err
	}
	if err = h.Validate(name); err != nil {
		return nil, err
	}
	return &h, nil
}

// Revision is optional opaque logging metadata, never a concurrency token.
type Revision struct {
	value   string
	present bool
}

// IsZero distinguishes omitted metadata from a provider-supplied empty string.
func (r Revision) IsZero() bool                 { return !r.present }
func (r Revision) String() string               { return r.value }
func (r Revision) MarshalJSON() ([]byte, error) { return json.Marshal(r.value) }

func (r *Revision) UnmarshalJSON(data []byte) error {
	if !utf8.Valid(data) || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("revision must be a string")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if len(value) > 256 || !utf8.ValidString(value) {
		return fmt.Errorf("revision exceeds 256 UTF-8 bytes or is invalid UTF-8")
	}
	*r = Revision{value: value, present: true}
	return nil
}

type User struct {
	ID         string            `json:"id"`
	Names      object.Strings    `json:"name"`
	UserName   string            `json:"userName,omitempty"`
	Attributes object.Attributes `json:"attributes,omitempty"`
	Groups     []object.Object   `json:"groups"`
	Revision   Revision          `json:"revision,omitzero"`
}

// PolicyUser retains the validated authorization facts and drops logging metadata.
func (u User) PolicyUser() wire.User {
	return wire.User{ID: u.ID, Names: u.Names, UserName: u.UserName, Attributes: u.Attributes, Groups: u.Groups}
}
