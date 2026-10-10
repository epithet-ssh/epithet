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

// SCIMRequest preserves the public provisioning operation across the signed hop,
// including its conditional-write precondition and complete query parameters.
type SCIMRequest struct {
	Method      string `json:"method"`
	Target      string `json:"target"`
	ContentType string `json:"contentType"`
	IfMatch     string `json:"ifMatch"`
	Body        []byte `json:"body"`
}

// SCIMResult owns the provisioning response body and SCIM-relevant metadata.
// SCIM success and error statuses are results; transport failures are Go errors.
type SCIMResult struct {
	Status                                       int
	ContentType, ETag, Location, WWWAuthenticate string
	Body                                         []byte
}

// ControlClient owns signed administration and provisioning operations against
// private directory and inventory backends. It never accepts a user bearer token
// and never exposes raw HTTP requests or responses.
type ControlClient struct{ directory, inventory *transport }

// NewControlClient configures the enabled private backends. An empty endpoint
// omits that backend; its operations report unavailable capabilities. Both may
// be omitted when control uses alternative read-only fact providers.
func NewControlClient(directoryURL, inventoryURL string, key sshcert.RawPrivateKey, cfg tlsconfig.Config) (*ControlClient, error) {
	c := &ControlClient{}
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

const controlResponseLimit = 8 << 20

func decodeControl(resp *exchange, result any, allowPending bool) error {
	if resp.status != http.StatusOK && !(allowPending && resp.status == http.StatusAccepted) {
		if resp.status >= 200 && resp.status < 300 {
			return fmt.Errorf("%w: unexpected control response status %d", ErrUnavailable, resp.status)
		}
		var rejected ControlResponse
		_ = json.Unmarshal(resp.body, &rejected)
		message := rejected.Error
		if message == "" {
			message = strings.TrimSpace(string(resp.body))
		}
		return &ServiceError{Status: resp.status, Message: message}
	}
	if err := json.Unmarshal(resp.body, result); err != nil {
		return fmt.Errorf("%w: invalid control response: %v", ErrUnavailable, err)
	}
	return nil
}

func (c *ControlClient) call(ctx context.Context, service *transport, auth Authorization, request ControlRequest) (*ControlResponse, error) {
	body, err := json.Marshal(ControlEnvelope{Request: request, AuthorizationRevision: auth.DirectoryRevision})
	if err != nil {
		return nil, err
	}
	resp, err := service.request(ctx, "POST", "/manage", nil, body, auth.Actor, controlResponseLimit)
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
	for _, service := range []*transport{c.directory, c.inventory} {
		if service == nil {
			continue
		}
		resp, err := service.request(ctx, "GET", "/manage", nil, nil, "", 65536)
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
	return result, nil
}

// Actor returns the administrator's current facts and authorization revision.
// Absence is nil; inactive users are returned so control can deny them explicitly.
func (c *ControlClient) Actor(ctx context.Context, id string) (*Actor, string, error) {
	resp, err := c.directory.request(ctx, "GET", "/actor", url.Values{"id": {id}}, nil, "", wire.MaxBodySize)
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

// Enroll is a nonhuman operation; the optional single-use token grants the
// existing preapproval. Pending enrollment is represented by the record status.
func (c *ControlClient) Enroll(ctx context.Context, proposal Proposal, token string) (*HostRecord, error) {
	return c.host(ctx, Authorization{}, ControlRequest{Action: "enroll", Host: &proposal, Token: token})
}

// AddPattern creates an active pattern record under the supplied administrator.
func (c *ControlClient) AddPattern(ctx context.Context, auth Authorization, proposal Proposal) (*HostRecord, error) {
	return c.host(ctx, auth, ControlRequest{Action: "add-pattern", Host: &proposal})
}

// Host returns a managed record by ID, including pending and denied records.
func (c *ControlClient) Host(ctx context.Context, auth Authorization, id string) (*HostRecord, error) {
	return c.host(ctx, auth, ControlRequest{Action: "get", ID: id})
}

// EditHost replaces a reviewed proposal using its exact record revision.
func (c *ControlClient) EditHost(ctx context.Context, auth Authorization, id string, revision uint64, proposal Proposal) (*HostRecord, error) {
	return c.host(ctx, auth, ControlRequest{Action: "edit", ID: id, Revision: revision, Host: &proposal})
}

// ApproveHost activates a pending record at its exact reviewed revision.
func (c *ControlClient) ApproveHost(ctx context.Context, auth Authorization, id string, revision uint64) (*HostRecord, error) {
	return c.host(ctx, auth, ControlRequest{Action: "approve", ID: id, Revision: revision})
}

// DenyHost denies a pending record at its exact reviewed revision.
func (c *ControlClient) DenyHost(ctx context.Context, auth Authorization, id string, revision uint64) (*HostRecord, error) {
	return c.host(ctx, auth, ControlRequest{Action: "deny", ID: id, Revision: revision})
}

// RemoveHost deletes the record using its exact reviewed revision.
func (c *ControlClient) RemoveHost(ctx context.Context, auth Authorization, id string, revision uint64) error {
	_, err := c.call(ctx, c.inventory, auth, ControlRequest{Action: "remove", ID: id, Revision: revision})
	return err
}
func (c *ControlClient) host(ctx context.Context, auth Authorization, request ControlRequest) (*HostRecord, error) {
	result, err := c.call(ctx, c.inventory, auth, request)
	if err != nil {
		return nil, err
	}
	if result.Host == nil {
		return nil, fmt.Errorf("%w: missing host record", ErrUnavailable)
	}
	return result.Host, nil
}

// Hosts returns one ID-ordered page of managed records, optionally restricted
// to pending records. Empty after starts enumeration; zero limit defaults to 100.
func (c *ControlClient) Hosts(ctx context.Context, auth Authorization, after string, limit int, pending bool) ([]HostRecord, error) {
	result, err := c.call(ctx, c.inventory, auth, ControlRequest{Action: "list", After: after, Limit: limit, Pending: pending})
	if err != nil {
		return nil, err
	}
	return result.Hosts, nil
}

// CreateToken creates a single-use enrollment token. Lifetime is in seconds;
// zero retains the backend default lifetime.
func (c *ControlClient) CreateToken(ctx context.Context, auth Authorization, lifetimeSeconds int64) (*EnrollmentToken, error) {
	result, err := c.call(ctx, c.inventory, auth, ControlRequest{Action: "token-create", LifetimeSeconds: lifetimeSeconds})
	if err != nil {
		return nil, err
	}
	if result.Token == nil {
		return nil, fmt.Errorf("%w: missing enrollment token", ErrUnavailable)
	}
	return result.Token, nil
}

// Tokens returns one ID-ordered page of enrollment tokens, including used and
// revoked tokens. Empty after starts enumeration; zero limit defaults to 100.
func (c *ControlClient) Tokens(ctx context.Context, auth Authorization, after string, limit int) ([]EnrollmentToken, error) {
	result, err := c.call(ctx, c.inventory, auth, ControlRequest{Action: "token-list", After: after, Limit: limit})
	if err != nil {
		return nil, err
	}
	return result.Tokens, nil
}

// RevokeToken revokes the identified enrollment token.
func (c *ControlClient) RevokeToken(ctx context.Context, auth Authorization, id string) error {
	_, err := c.call(ctx, c.inventory, auth, ControlRequest{Action: "token-revoke", ID: id})
	return err
}

// HostAudit returns one page of inventory events after an exclusive sequence
// cursor. Zero starts at the beginning; zero limit defaults to 100.
func (c *ControlClient) HostAudit(ctx context.Context, auth Authorization, after uint64, limit int) ([]HostAuditEvent, error) {
	result, err := c.call(ctx, c.inventory, auth, ControlRequest{Action: "audit", AuditAfter: after, AuditLimit: limit})
	if err != nil {
		return nil, err
	}
	return result.Audit, nil
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

// Bindings returns group bindings and the revision that binds their review.
func (c *ControlClient) Bindings(ctx context.Context, auth Authorization) (*BindingSnapshot, error) {
	result, err := c.call(ctx, c.directory, auth, ControlRequest{Action: "directory-groups"})
	if err != nil {
		return nil, err
	}
	if result.Directory == nil {
		return nil, fmt.Errorf("%w: missing binding snapshot", ErrUnavailable)
	}
	return result.Directory, nil
}

// BindGroup changes a reviewed binding. Authorization.DirectoryRevision binds
// the write to the same directory snapshot that authorized the administrator.
func (c *ControlClient) BindGroup(ctx context.Context, auth Authorization, alias, id string, revision uint64) error {
	_, err := c.call(ctx, c.directory, auth, ControlRequest{Action: "directory-bind", Alias: alias, ID: id, Revision: revision})
	return err
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

// Provision executes a SCIM operation using the control service key, with no
// human actor. The result retains SCIM status, format, preconditions and location.
func (c *ControlClient) Provision(ctx context.Context, request SCIMRequest) (*SCIMResult, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := c.directory.request(ctx, "POST", "/scim", nil, body, "", controlResponseLimit)
	if err != nil {
		return nil, err
	}
	return &SCIMResult{Status: resp.status, Body: resp.body, ContentType: resp.contentType, ETag: resp.etag, Location: resp.location, WWWAuthenticate: resp.authenticate}, nil
}
