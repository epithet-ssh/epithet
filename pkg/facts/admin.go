package facts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

const MaxControlResponse = 8 << 20

// AdminClient sends public directory and inventory administration requests
// using the caller's bearer credential. Private provider requests signed with
// control's service key belong to pkg/facts/control.
type AdminClient struct {
	httpClient *http.Client
	endpoint   string
}

// NewAdminClient binds a client to the complete public administration URL.
// An empty endpoint means the CA does not advertise managed inventory.
func NewAdminClient(endpoint string, cfg tlsconfig.Config) (*AdminClient, error) {
	if endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid inventory URL")
		}
		if err := cfg.ValidateURL(endpoint); err != nil {
			return nil, err
		}
	}
	client, err := tlsconfig.NewHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &AdminClient{httpClient: client, endpoint: endpoint}, nil
}

// Control sends a single operation to the configured endpoint. Callers
// choose the credential for this operation; redirects never receive it.
func (c *AdminClient) Control(ctx context.Context, bearer string, request ControlRequest) (*ControlResponse, int, error) {
	if c.endpoint == "" {
		return nil, 0, fmt.Errorf("CA does not advertise managed inventory")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxControlResponse+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(body) > MaxControlResponse {
		return nil, response.StatusCode, fmt.Errorf("inventory response exceeds size limit")
	}
	var result ControlResponse
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, response.StatusCode, fmt.Errorf("invalid inventory response (HTTP %d)", response.StatusCode)
	}
	if response.StatusCode != 200 && response.StatusCode != 202 {
		return &result, response.StatusCode, fmt.Errorf("inventory: %s (HTTP %d)", strings.TrimSpace(result.Error), response.StatusCode)
	}
	return &result, response.StatusCode, nil
}

// Capabilities reads configured capabilities before host enrollment. Directory
// administration alone does not enable managed host enrollment. Errors must not
// be interpreted as absence: an outage cannot select static enrollment.
func (c *AdminClient) Capabilities(ctx context.Context) (Capabilities, error) {
	var result Capabilities
	req, err := http.NewRequestWithContext(ctx, "GET", c.endpoint, nil)
	if err != nil {
		return result, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("inventory capability discovery failed (HTTP %d)", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return result, err
	}
	if len(data) > 65536 {
		return result, fmt.Errorf("inventory capability response exceeds size limit")
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("invalid inventory capability response")
	}
	if result.Version != 1 || result.Capabilities == nil {
		return result, fmt.Errorf("invalid inventory capabilities")
	}
	return result, nil
}

var (
	ErrInvalid     = errors.New("invalid service operation")
	ErrNotFound    = errors.New("service resource not found")
	ErrDenied      = errors.New("service operation denied")
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
	case e.Status >= 500:
		return target == ErrUnavailable
	}
	return false
}

// ControlEnvelope carries a private backend request. Control owns the sender;
// providers decode this envelope at the boundary.
type ControlEnvelope struct {
	Request ControlRequest `json:"request"`
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
type ActorSnapshot struct {
	User *Actor `json:"user"`
}

// Public administration records below are protocol shapes, independent of
// persisted directory and inventory records. Service adapters convert between them.

// ControlRequest is one operation at the complete advertised inventory URL.
// An optional single-use token preapproves enrollment. Admin authentication is
// the OIDC bearer header. Revision binds review/edit to the displayed record.
// Host lists use exclusive After IDs and Limit (0 defaults to 100,
// maximum 1000); Pending filters host lists. Audits use opaque AuditCursor values
// and AuditLimit with the same bounds. Cursor fields survive JSON as exact values.
type ControlRequest struct {
	After           string          `json:"after,omitempty"`
	Limit           int             `json:"limit,omitempty"`
	Pending         bool            `json:"pending,omitempty"`
	AuditCursor     string          `json:"audit-cursor,omitempty"`
	AuditLimit      int             `json:"audit-limit,omitempty"`
	Action          string          `json:"action"`
	ID              string          `json:"id,omitempty"`
	Revision        uint64          `json:"revision,omitempty"`
	Host            *InventoryInput `json:"host,omitempty"`
	Token           string          `json:"token,omitempty"`
	LifetimeSeconds int64           `json:"lifetime-seconds,omitempty"`
}

// ControlResponse carries the result of one ControlRequest. Only the fields
// relevant to the requested action are set; Error accompanies a non-2xx status.
type ControlResponse struct {
	DirectoryAudit *AuditPage[DirectoryAuditEvent] `json:"directory-audit,omitempty"`
	Host           *HostRecord                     `json:"host,omitempty"`
	Hosts          []HostRecord                    `json:"hosts,omitempty"`
	Token          *EnrollmentToken                `json:"token,omitempty"`
	Audit          *AuditPage[HostAuditEvent]      `json:"audit,omitempty"`
	Error          string                          `json:"error,omitempty"`
}

// Capabilities distinguishes host enrollment from directory-only administration.
// An unavailable or malformed endpoint is an error, never static fallback.
type Capabilities struct {
	Version      int      `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// InventoryInput is the editable control-protocol payload for a host. Admission
// and ownership are server-owned metadata, never fields a host can approve for
// itself. Accounts nil means unrestricted; an empty list permits no accounts.
type InventoryInput struct {
	Names         []string          `json:"names"`
	Labels        map[string]string `json:"labels"`
	Accounts      []string          `json:"accounts"`
	PrincipalMode string            `json:"principal-mode"`
	Realm         string            `json:"realm,omitempty"`
}

// UnmarshalJSON requires accounts at the input boundary. Explicit null is
// unrestricted; [] permits none. Accidentally omitting the field must not
// broaden access, so omission is an error rather than a default.
func (p *InventoryInput) UnmarshalJSON(data []byte) error {
	type plain InventoryInput
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["accounts"]; !ok {
		return fmt.Errorf("accounts must be explicit")
	}
	var raw plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	*p = InventoryInput(raw)
	return nil
}

// HostRecord is one managed inventory record as administrators see it.
type HostRecord struct {
	ID        string         `json:"id"`
	Revision  uint64         `json:"revision"`
	Status    string         `json:"status"`
	Host      InventoryInput `json:"host"`
	CreatedAt time.Time      `json:"created-at"`
	UpdatedAt time.Time      `json:"updated-at"`
}

// EnrollmentToken is a single-use preapproval for host enrollment.
type EnrollmentToken struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires-at"`
	UsedBy    string    `json:"used-by,omitempty"`
	Revoked   bool      `json:"revoked"`
}

// AuditPage contains events and a backend-owned continuation cursor. Empty Next
// means there is no further page. Clients pass nonempty Next back unchanged.
type AuditPage[T any] struct {
	Events []T    `json:"events"`
	Next   string `json:"next,omitempty"`
}

// HostAuditEvent records one administrative change to host inventory.
type HostAuditEvent struct {
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Resource string    `json:"resource"`
}

// DirectoryAuditEvent records one directory mutation with its supplied timestamp.
type DirectoryAuditEvent struct {
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	ID         string    `json:"id"`
	Alias      string    `json:"alias,omitempty"`
	PreviousID string    `json:"previous-id,omitempty"`
}

// SCIMPage is one bounded SCIM ListResponse. Resources retain their original
// attributes, including extensions; callers must process a page before fetching
// the next one rather than accumulate the directory in memory.
type SCIMPage struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

// ListUsers reads one SCIM page through control using the caller's bearer token.
// Control exposes /scim/v2/Users on the same origin as its administration URL;
// provider addressing/discovery remains control's responsibility. start is
// one-based. Each request asks for at most 100 users and bounds the response body.
// Status is returned even on errors so the agent can refresh a rejected token.
func (c *AdminClient) ListUsers(ctx context.Context, bearer string, start int) (*SCIMPage, int, error) {
	return c.listSCIM(ctx, bearer, "Users", start)
}

// ListGroups reads one SCIM group page, with the same bounds and authentication
// behavior as ListUsers. Resources include the group's complete membership.
func (c *AdminClient) ListGroups(ctx context.Context, bearer string, start int) (*SCIMPage, int, error) {
	return c.listSCIM(ctx, bearer, "Groups", start)
}

func (c *AdminClient) listSCIM(ctx context.Context, bearer, resource string, start int) (*SCIMPage, int, error) {
	const pageSize = 100
	if start < 1 || start > int(^uint(0)>>1)-pageSize {
		return nil, 0, fmt.Errorf("invalid SCIM startIndex")
	}
	if c.endpoint == "" {
		return nil, 0, fmt.Errorf("CA does not advertise control administration")
	}
	target, err := url.Parse(c.endpoint)
	if err != nil {
		return nil, 0, err
	}
	target.Path, target.RawPath = "/scim/v2/"+resource, ""
	target.RawQuery = url.Values{"startIndex": {fmt.Sprint(start)}, "count": {fmt.Sprint(pageSize)}}.Encode()
	target.ForceQuery = false
	req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/scim+json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxControlResponse+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > MaxControlResponse {
		return nil, resp.StatusCode, fmt.Errorf("SCIM page exceeds size limit")
	}
	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(body, &failure)
		if resp.StatusCode == http.StatusNotFound {
			return nil, resp.StatusCode, fmt.Errorf("directory does not support SCIM listing")
		}
		return nil, resp.StatusCode, fmt.Errorf("SCIM listing: %s (HTTP %d)", strings.TrimSpace(failure.Detail), resp.StatusCode)
	}
	var page SCIMPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("invalid SCIM page: %w", err)
	}
	if !slices.Contains(page.Schemas, "urn:ietf:params:scim:api:messages:2.0:ListResponse") ||
		page.StartIndex != start || page.TotalResults < 0 || page.ItemsPerPage < len(page.Resources) ||
		page.ItemsPerPage > pageSize || len(page.Resources) > pageSize ||
		(len(page.Resources) == 0 && start <= page.TotalResults) ||
		(len(page.Resources) > 0 && (start-1 >= page.TotalResults || len(page.Resources) > page.TotalResults-(start-1))) {
		return nil, resp.StatusCode, fmt.Errorf("invalid SCIM pagination")
	}
	return &page, resp.StatusCode, nil
}
