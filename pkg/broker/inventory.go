package broker

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
)

// InventoryWithUserOutput sends an administrative operation through the agent's
// CA-discovered inventory endpoint. Only the short-lived ID token goes to that
// endpoint; no token or refresh state is returned over the local protocol.
func (b *Broker) InventoryWithUserOutput(ctx context.Context, request facts.ControlRequest, out io.Writer) *InventoryResponse {
	session, ctx, cancel := b.sessionRequest(ctx)
	defer cancel()
	logger := b.log.With("action", request.Action)
	started := time.Now()
	defer func() { logger.Debug("inventory request ended", "elapsed", time.Since(started)) }()
	fail := func(err error) *InventoryResponse {
		logger.Debug("inventory request failed", "error", err)
		return &InventoryResponse{ControlResponse: facts.ControlResponse{Error: err.Error()}}
	}
	logger.Debug("authenticating inventory request")
	token, err := session.auth.Token(ctx, out)
	if err != nil {
		return fail(err)
	}
	logger.Debug("inventory authentication complete", "elapsed", time.Since(started))
	response, status, err := b.inventoryWithToken(ctx, token, request)
	if status == 401 {
		logger.Debug("inventory rejected authentication; refreshing token")
		token, err = session.auth.ForceRefresh(ctx, out)
		if err != nil {
			return fail(err)
		}
		response, _, err = b.inventoryWithToken(ctx, token, request)
	}
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	result := &InventoryResponse{ControlResponse: *response}
	if response.Token != nil {
		result.CAURL = b.publicCAURL
	}
	return result
}

func (b *Broker) inventoryWithToken(ctx context.Context, token string, request facts.ControlRequest) (*facts.ControlResponse, int, error) {
	started := time.Now()
	b.log.Debug("sending inventory HTTP request", "action", request.Action)
	response, status, err := b.inventoryClient.Control(ctx, token, request)
	b.log.Debug("inventory HTTP request ended", "action", request.Action, "status", status, "elapsed", time.Since(started))
	return response, status, err
}

// listDirectoryWithUserOutput authenticates one SCIM page request. The CLI advances
// the cursor after consuming each page, so neither the broker nor control holds
// an entire directory. Authentication refresh follows other admin operations.
func (b *Broker) listDirectoryWithUserOutput(ctx context.Context, request DirectoryListRequest, out io.Writer) *DirectoryListResponse {
	session, ctx, cancel := b.sessionRequest(ctx)
	defer cancel()
	fail := func(err error) *DirectoryListResponse { return &DirectoryListResponse{Error: err.Error()} }
	list := b.inventoryClient.ListUsers
	switch request.Resource {
	case "Users":
	case "Groups":
		list = b.inventoryClient.ListGroups
	default:
		return fail(fmt.Errorf("unknown directory resource %q", request.Resource))
	}
	token, err := session.auth.Token(ctx, out)
	if err != nil {
		return fail(err)
	}
	page, status, err := list(ctx, token, request.StartIndex)
	if status == 401 {
		token, err = session.auth.ForceRefresh(ctx, out)
		if err != nil {
			return fail(err)
		}
		page, _, err = list(ctx, token, request.StartIndex)
	}
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return &DirectoryListResponse{Page: page}
}
