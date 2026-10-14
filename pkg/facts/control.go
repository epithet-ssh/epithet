package facts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

var (
	ErrInvalid     = errors.New("invalid service operation")
	ErrNotFound    = errors.New("service resource not found")
	ErrDenied      = errors.New("service operation denied")
	ErrConflict    = errors.New("service revision or uniqueness conflict")
	ErrUnavailable = errors.New("service unavailable")
)

// ServiceError preserves a rejected operation's message and protocol status for
// the public HTTP adapter. Callers can use errors.Is for domain error categories.
type ServiceError struct {
	Status  int
	Message string
}

func (e *ServiceError) Error() string { return e.Message }
func (e *ServiceError) Is(target error) bool {
	switch {
	case e.Status == 400:
		return target == ErrInvalid
	case e.Status == 401 || e.Status == 403:
		return target == ErrDenied
	case e.Status == 404:
		return target == ErrNotFound
	case e.Status == 409 || e.Status == 412:
		return target == ErrConflict
	case e.Status >= 500:
		return target == ErrUnavailable
	}
	return false
}

// Authorization is the human identity and coherent directory revision already
// authorized by public control. The actor is signed in the service credential;
// the revision is signed in the request body. The client does not grant roles.
type Authorization struct {
	Actor             string
	DirectoryRevision string
}

// ControlEnvelope is the existing private backend wire contract. Senders use
// typed ControlClient operations; backends decode this envelope at the boundary.
type ControlEnvelope struct {
	Request               ControlRequest `json:"request"`
	AuthorizationRevision string         `json:"authorizationRevision,omitempty"`
}

// Actor carries the directory identity used for public administrative grants.
// Its field names preserve the private actor-snapshot JSON contract; it includes
// inactive identities so the public service can reject them explicitly.
type Actor struct {
	UserName     string
	ID           string
	Active       bool
	Groups       []string
	UserType     string
	Department   string
	Organization string
}

// ActorSnapshot includes inactive users for administrative authorization checks.
// Its revision identifies the same snapshot as the returned user.
type ActorSnapshot struct {
	User     *Actor `json:"user"`
	Revision string `json:"authorizationRevision"`
}

// ControlClient owns signed administration operations against
// private directory and inventory backends. It never accepts a user bearer token
// and never exposes raw HTTP requests or responses.
type ControlClient struct{ directory, inventory *servicehttp.Client }

// NewControlClient takes a directory service root and a complete inventory fact
// endpoint. Inventory management is discovered there using OPTIONS. An empty endpoint
// omits that backend; its operations report unavailable capabilities. Both may
// be omitted when control uses alternative read-only fact providers.
func NewControlClient(directoryURL, inventoryURL string, key sshcert.RawPrivateKey, cfg tlsconfig.Config) (*ControlClient, error) {
	c := &ControlClient{}
	var err error
	if directoryURL != "" {
		c.directory, err = servicehttp.New(directoryURL, "", key, serviceauth.DirectoryAudience, cfg)
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

const controlResponseLimit = 8 << 20

// directoryRequest implements the built-in directory's root-relative actor and
// management endpoints. Resource discovery belongs to the other protocols.
func directoryRequest(ctx context.Context, service *servicehttp.Client, method, path string, query url.Values, body []byte, actor string, limit int64) (*servicehttp.Response, error) {
	if service == nil {
		return nil, &ServiceError{Status: 404, Message: "requested inventory capability is not configured"}
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
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return resp, nil
}

func decodeControl(resp *servicehttp.Response, result any, allowPending bool) error {
	if resp.Status != http.StatusOK && !(allowPending && resp.Status == http.StatusAccepted) {
		if resp.Status >= 200 && resp.Status < 300 {
			return fmt.Errorf("%w: unexpected control response status %d", ErrUnavailable, resp.Status)
		}
		var rejected ControlResponse
		_ = json.Unmarshal(resp.Body, &rejected)
		message := rejected.Error
		if message == "" {
			message = strings.TrimSpace(string(resp.Body))
		}
		return &ServiceError{Status: resp.Status, Message: message}
	}
	if err := json.Unmarshal(resp.Body, result); err != nil {
		return fmt.Errorf("%w: invalid control response: %v", ErrUnavailable, err)
	}
	return nil
}

func (c *ControlClient) call(ctx context.Context, service *servicehttp.Client, auth Authorization, request ControlRequest) (*ControlResponse, error) {
	body, err := json.Marshal(ControlEnvelope{Request: request, AuthorizationRevision: auth.DirectoryRevision})
	if err != nil {
		return nil, err
	}
	resp, err := directoryRequest(ctx, service, "POST", "/manage", nil, body, auth.Actor, controlResponseLimit)
	if err != nil {
		return nil, err
	}
	var result ControlResponse
	if err = decodeControl(resp, &result, request.Action == "enroll"); err != nil {
		return nil, err
	}
	return &result, nil
}

// Capabilities combines the enabled backends' supported operations. Failure to
// read a backend is an error, never evidence that its capabilities are absent.
func (c *ControlClient) Capabilities(ctx context.Context) (Capabilities, error) {
	result := Capabilities{Version: 1, Capabilities: []string{"admin"}}
	for _, service := range []*servicehttp.Client{c.directory} {
		if service == nil {
			continue
		}
		resp, err := directoryRequest(ctx, service, "GET", "/manage", nil, nil, "", 65536)
		if err != nil {
			return result, err
		}
		var caps Capabilities
		if err = decodeControl(resp, &caps, false); err != nil {
			return result, err
		}
		if caps.Version != 1 || caps.Capabilities == nil {
			return result, fmt.Errorf("%w: invalid backend capabilities", ErrUnavailable)
		}
		for _, cap := range caps.Capabilities {
			if !slices.Contains(result.Capabilities, cap) {
				result.Capabilities = append(result.Capabilities, cap)
			}
		}
	}
	templates, err := c.inventoryTemplates(ctx)
	if err != nil {
		return result, err
	}
	if len(templates) != 0 {
		result.Capabilities = append(result.Capabilities, "enroll")
	}
	return result, nil
}

// Actor returns the administrator's current facts and authorization revision.
// Absence is nil; inactive users are returned so control can deny them explicitly.
func (c *ControlClient) Actor(ctx context.Context, id string) (*Actor, string, error) {
	resp, err := directoryRequest(ctx, c.directory, "GET", "/actor", url.Values{"id": {id}}, nil, "", wire.MaxBodySize)
	if err != nil {
		return nil, "", err
	}
	var result ActorSnapshot
	if err = decodeControl(resp, &result, false); err != nil {
		return nil, "", err
	}
	if result.User != nil && result.User.ID != id {
		return nil, "", fmt.Errorf("actor identity mismatch")
	}
	return result.User, result.Revision, nil
}

// Users returns the complete directory authorization snapshot.
func (c *ControlClient) Users(ctx context.Context, auth Authorization) (*UserSnapshot, error) {
	result, err := c.call(ctx, c.directory, auth, ControlRequest{Action: "directory-users"})
	if err != nil {
		return nil, err
	}
	if result.DirectoryUsers == nil {
		return nil, fmt.Errorf("%w: missing user snapshot", ErrUnavailable)
	}
	return result.DirectoryUsers, nil
}

// Groups returns current directory group names and identifiers.
func (c *ControlClient) Groups(ctx context.Context, auth Authorization) (*GroupSnapshot, error) {
	result, err := c.call(ctx, c.directory, auth, ControlRequest{Action: "directory-groups"})
	if err != nil {
		return nil, err
	}
	if result.Directory == nil {
		return nil, fmt.Errorf("%w: missing group snapshot", ErrUnavailable)
	}
	return result.Directory, nil
}

// DirectoryAudit reads at most limit events after the exclusive sequence
// cursor. Zero limit retains the backend default.
func (c *ControlClient) DirectoryAudit(ctx context.Context, auth Authorization, after uint64, limit int) ([]DirectoryAuditEvent, error) {
	result, err := c.call(ctx, c.directory, auth, ControlRequest{Action: "directory-audit", AuditAfter: after, AuditLimit: limit})
	if err != nil {
		return nil, err
	}
	return result.DirectoryAudit, nil
}
