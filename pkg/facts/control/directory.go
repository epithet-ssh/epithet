package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

const controlResponseLimit = 8 << 20

// directoryRequest implements the built-in directory's root-relative actor and
// management endpoints. Resource discovery belongs to the other protocols.
func directoryRequest(ctx context.Context, service *servicehttp.Client, method, path string, query url.Values, body []byte, actor string, limit int64) (*servicehttp.Response, error) {
	if service == nil {
		return nil, &facts.ServiceError{Status: 404, Message: "requested inventory capability is not configured"}
	}
	target, err := url.Parse(strings.TrimRight(service.Endpoint(), "/") + path)
	if err != nil {
		return nil, err
	}
	target.RawQuery = query.Encode()
	contentType := ""
	if body != nil {
		contentType = "application/json"
	}
	resp, err := service.Do(ctx, servicehttp.Request{Method: method, URL: target.String(), Body: body, Actor: actor, ContentType: contentType}, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", facts.ErrUnavailable, err)
	}
	return resp, nil
}

func decodeControl(resp *servicehttp.Response, result any) error {
	if resp.Status != http.StatusOK {
		if resp.Status >= 200 && resp.Status < 300 {
			return fmt.Errorf("%w: unexpected control response status %d", facts.ErrUnavailable, resp.Status)
		}
		var rejected facts.ControlResponse
		_ = json.Unmarshal(resp.Body, &rejected)
		message := rejected.Error
		if message == "" {
			message = strings.TrimSpace(string(resp.Body))
		}
		return &facts.ServiceError{Status: resp.Status, Message: message}
	}
	if err := json.Unmarshal(resp.Body, result); err != nil {
		return fmt.Errorf("%w: invalid control response: %v", facts.ErrUnavailable, err)
	}
	return nil
}

func (c *Server) directoryCall(ctx context.Context, auth authorization, request facts.ControlRequest) (*facts.ControlResponse, error) {
	body, err := json.Marshal(facts.ControlEnvelope{Request: request})
	if err != nil {
		return nil, err
	}
	resp, err := directoryRequest(ctx, c.directoryBackend, "POST", "/manage", nil, body, auth.Actor, controlResponseLimit)
	if err != nil {
		return nil, err
	}
	var result facts.ControlResponse
	if err = decodeControl(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// directoryActor returns the administrator's current facts.
// Absence is nil; inactive users are returned so control can deny them explicitly.
func (c *Server) directoryActor(ctx context.Context, id string) (*facts.Actor, error) {
	resp, err := directoryRequest(ctx, c.directoryBackend, "GET", "/actor", url.Values{"id": {id}}, nil, "", wire.MaxBodySize)
	if err != nil {
		return nil, err
	}
	var result facts.ActorSnapshot
	if err = decodeControl(resp, &result); err != nil {
		return nil, err
	}
	if result.User != nil && result.User.ID != id {
		return nil, fmt.Errorf("actor identity mismatch")
	}
	return result.User, nil
}

// directoryAudit forwards the backend cursor unchanged. Zero limit retains
// the backend default.
func (c *Server) directoryAudit(ctx context.Context, auth authorization, cursor string, limit int) (*facts.AuditPage[facts.DirectoryAuditEvent], error) {
	result, err := c.directoryCall(ctx, auth, facts.ControlRequest{Action: "directory-audit", AuditCursor: cursor, AuditLimit: limit})
	if err != nil {
		return nil, err
	}
	return result.DirectoryAudit, nil
}
