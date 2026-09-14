package broker

import (
	"context"
	"io"
	"time"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
)

// InventoryWithUserOutput sends an administrative operation through the agent's
// CA-discovered inventory endpoint. Only the short-lived ID token goes to that
// endpoint; no token or refresh state is returned over the local protocol.
func (b *Broker) InventoryWithUserOutput(ctx context.Context, request inventoryapi.ControlRequest, out io.Writer) *inventoryapi.ControlResponse {
	logger := b.log.With("action", request.Action)
	started := time.Now()
	defer func() { logger.Debug("inventory request ended", "elapsed", time.Since(started)) }()
	fail := func(err error) *inventoryapi.ControlResponse {
		logger.Debug("inventory request failed", "error", err)
		return &inventoryapi.ControlResponse{Error: err.Error()}
	}
	logger.Debug("authenticating inventory request")
	token, err := b.auth.Token(ctx, out)
	if err != nil {
		return fail(err)
	}
	logger.Debug("inventory authentication complete", "elapsed", time.Since(started))
	response, status, err := b.inventoryWithToken(ctx, token, request)
	if status == 401 {
		logger.Debug("inventory rejected authentication; refreshing token")
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
	started := time.Now()
	b.log.Debug("sending inventory HTTP request", "action", request.Action)
	response, status, err := b.inventoryClient.Control(ctx, token, request)
	b.log.Debug("inventory HTTP request ended", "action", request.Action, "status", status, "elapsed", time.Since(started))
	if response != nil && response.Token != nil {
		response.CAURL = b.publicCAURL
	}
	return response, status, err
}
