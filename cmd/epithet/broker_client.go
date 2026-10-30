package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// brokerClient owns the agent's local request/event protocol. Each operation
// opens one connection, streams authentication progress, and returns its typed
// result. Commands own socket selection, deadlines, and presentation.
type brokerClient struct{ socket string }

const scannerBufferSize = 1024 * 1024

func (c brokerClient) exchange(ctx context.Context, request broker.Request, progress io.Writer) (*broker.Event, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to agent at %s; start it with epithet agent: %w", c.socket, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, fmt.Errorf("sending agent request: %w", err)
	}

	limit := scannerBufferSize
	if request.Inventory != nil || request.DirectoryList != nil {
		limit = facts.MaxControlResponse
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), limit)
	for scanner.Scan() {
		var event broker.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("reading agent response: %w", err)
		}
		if event.Output != "" && progress != nil {
			if _, err := io.WriteString(progress, event.Output); err != nil {
				return nil, err
			}
		}
		// Result also carries protocol/dispatch failures for non-match requests.
		if event.Result != nil ||
			(request.Identity != nil && event.Identity != nil) ||
			(request.Inventory != nil && event.Inventory != nil) ||
			(request.DirectoryList != nil && event.DirectoryList != nil) ||
			(request.Inspect != nil && event.Inspect != nil) ||
			(request.Kill != nil && event.Kill != nil) ||
			(request.Logout != nil && event.Logout != nil) {
			return &event, nil
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading agent response: %w", err)
	}
	return nil, fmt.Errorf("agent closed connection without a response")
}

func (c brokerClient) identity(ctx context.Context, progress io.Writer, loginMethod string) (*broker.Identity, error) {
	if loginMethod == "auto" {
		loginMethod = ""
	}
	event, err := c.exchange(ctx, broker.Request{Identity: &broker.IdentityRequest{LoginMethod: loginMethod}}, progress)
	if err != nil {
		return nil, err
	}
	if event.Identity == nil {
		return nil, fmt.Errorf("agent identity: %s (restart the agent if it predates identity support)", event.Result.Error)
	}
	if event.Identity.Error != "" {
		return nil, fmt.Errorf("agent identity: %s", event.Identity.Error)
	}
	if event.Identity.Identity == nil {
		return nil, fmt.Errorf("agent returned no identity")
	}
	return event.Identity.Identity, nil
}

func (c brokerClient) logout(ctx context.Context) (*broker.LogoutResponse, error) {
	event, err := c.exchange(ctx, broker.Request{Logout: &struct{}{}}, nil)
	if err != nil {
		return nil, err
	}
	if event.Logout == nil {
		return nil, fmt.Errorf("agent returned no logout response; restart the agent if it predates logout support")
	}
	if event.Logout.Error != "" {
		return nil, fmt.Errorf("agent logout: %s", event.Logout.Error)
	}
	return event.Logout, nil
}

func (c brokerClient) kill(ctx context.Context, id wire.ConnectionHash) (*broker.KillResponse, error) {
	event, err := c.exchange(ctx, broker.Request{Kill: &broker.KillRequest{ID: id}}, nil)
	if err != nil {
		return nil, err
	}
	if event.Kill == nil {
		return nil, fmt.Errorf("broker error: %s", event.Result.Error)
	}
	if event.Kill.Error != "" {
		return nil, fmt.Errorf("broker refused to kill agent: %s", event.Kill.Error)
	}
	return event.Kill, nil
}

func (c brokerClient) inspect(ctx context.Context, id wire.ConnectionHash) (*broker.InspectResponse, error) {
	event, err := c.exchange(ctx, broker.Request{Inspect: &broker.InspectRequest{ID: id}}, nil)
	if err != nil {
		return nil, err
	}
	if event.Inspect == nil {
		return nil, fmt.Errorf("broker error: %s", event.Result.Error)
	}
	return event.Inspect, nil
}

// A denied match is a successful protocol exchange. The command translates
// Allow into SSH's exit status and displays Error as the broker's explanation.
func (c brokerClient) match(ctx context.Context, connection wire.Connection, progress io.Writer) (*broker.MatchResponse, error) {
	event, err := c.exchange(ctx, broker.Request{Match: &connection}, progress)
	if err != nil {
		return nil, err
	}
	return event.Result, nil
}

func (c brokerClient) manage(ctx context.Context, request facts.ControlRequest, progress io.Writer) (*broker.InventoryResponse, error) {
	event, err := c.exchange(ctx, broker.Request{Inventory: &request}, progress)
	if err != nil {
		return nil, err
	}
	if event.Inventory == nil {
		return nil, fmt.Errorf("agent rejected inventory request: %s", event.Result.Error)
	}
	if event.Inventory.Error != "" {
		return nil, errors.New(event.Inventory.Error)
	}
	return event.Inventory, nil
}

func (c brokerClient) directoryPage(ctx context.Context, resource string, start int, progress io.Writer) (*facts.SCIMPage, error) {
	event, err := c.exchange(ctx, broker.Request{DirectoryList: &broker.DirectoryListRequest{Resource: resource, StartIndex: start}}, progress)
	if err != nil {
		return nil, err
	}
	if event.DirectoryList == nil {
		return nil, fmt.Errorf("agent rejected directory listing: %s", event.Result.Error)
	}
	if event.DirectoryList.Error != "" {
		return nil, errors.New(event.DirectoryList.Error)
	}
	if event.DirectoryList.Page == nil {
		return nil, fmt.Errorf("agent omitted directory page")
	}
	return event.DirectoryList.Page, nil
}
