package broker

import (
	"context"
	"fmt"
	"io"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
)

// InventoryWithUserOutput sends an administrative operation through the agent's
// CA-discovered inventory endpoint. Only the short-lived ID token goes to that
// endpoint; no token or refresh state is returned over the local protocol.
func (b *Broker) InventoryWithUserOutput(ctx context.Context, request inventoryapi.ControlRequest, out io.Writer) *inventoryapi.ControlResponse {
	fail := func(err error) *inventoryapi.ControlResponse {
		return &inventoryapi.ControlResponse{Error: err.Error()}
	}
	token, err := b.auth.Token(ctx, out)
	if err != nil {
		return fail(err)
	}
	response, status, err := b.inventoryWithToken(ctx, token, request)
	if status == 401 {
		token, err = b.auth.ForceRefresh(ctx, out)
		if err != nil {
			return fail(err)
		}
		response, _, err = b.inventoryWithToken(ctx, token, request)
	}
	if err != nil {
		return fail(err)
	}
	return response
}

// WithInventoryClient configures inventory transport independently of CA transport.
func WithInventoryClient(client *inventoryclient.Client) Option {
	return optionFunc(func(b *Broker) error {
		if client == nil {
			return fmt.Errorf("inventory client is required")
		}
		b.inventoryClient = client
		return nil
	})
}

func (b *Broker) inventoryWithToken(ctx context.Context, token string, request inventoryapi.ControlRequest) (*inventoryapi.ControlResponse, int, error) {
	endpoint, caURL, err := b.caClient.DiscoverInventory(ctx)
	if err != nil {
		return nil, 0, err
	}
	if endpoint == "" {
		return nil, 0, fmt.Errorf("CA does not advertise managed inventory")
	}
	response, status, err := b.inventoryClient.Control(ctx, endpoint, token, request)
	if response != nil && response.Secret != "" {
		response.CAURL = caURL
	}
	return response, status, err
}
