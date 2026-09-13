package broker

import (
	"context"
	"io"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
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

func (b *Broker) inventoryWithToken(ctx context.Context, token string, request inventoryapi.ControlRequest) (*inventoryapi.ControlResponse, int, error) {
	response, status, err := b.inventoryClient.Control(ctx, token, request)
	if response != nil && response.Token != nil {
		response.CAURL = b.publicCAURL
	}
	return response, status, err
}
