package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/directory"
)

type Kind string

const (
	Users  Kind = "Users"
	Groups Kind = "Groups"
)

var (
	ErrInvalid  = errors.New("invalid directory resource")
	ErrNotFound = errors.New("directory resource not found")
	ErrConflict = errors.New("directory uniqueness conflict")
	ErrVersion  = errors.New("directory revision changed")
)

// Document retains provisioning attributes, including extensions not used for
// authorization. Protocol adapters validate and canonicalize it before storage;
// id, meta and computed user groups are owned by the service, not this document.
type Document map[string]json.RawMessage

// Resource is a persisted provisioning resource. ID is distinct from the
// provider externalId used by LookupUser and Writ. Version changes on every
// resource mutation, including membership cleanup caused by deleting a user.
type Resource struct {
	ID       string
	Kind     Kind
	Document Document
	Version  uint64
	Created  time.Time
	Modified time.Time
}

func (r Resource) ETag() string { return fmt.Sprintf(`W/"%d"`, r.Version) }

// Page contains one slice of SCIM resources and the total matching resource count.
// The HTTP handler combines it with the request offset to form a SCIM ListResponse.
type Page struct {
	Resources []Resource
	Total     int
}

type GroupBinding struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Alias       string `json:"alias,omitempty"`
	Status      string `json:"status"`
}

// BindingSnapshot lets administrators bind a review to the exact directory
// revision they inspected. Deleted bindings retain the former group ID.
type BindingSnapshot struct {
	Revision uint64         `json:"revision"`
	Groups   []GroupBinding `json:"groups"`
}

type AuditEvent struct {
	Revision   uint64    `json:"revision"`
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	ID         string    `json:"id"`
	Alias      string    `json:"alias,omitempty"`
	PreviousID string    `json:"previous-id,omitempty"`
}

// Store owns directory persistence and all changes to authorization indexes.
// Each mutation commits the resource, memberships, aliases, audit and revision
// together. No database handles or multi-call transaction protocol escape here.
// Get/List return independent snapshots; LookupUser resolves identity,
// memberships and aliases in a single read. Backend failures stay errors.
//
// Replace/Delete accept an optional resource ETag ("*" requires existence).
// A stale precondition never changes state. Rebind requires an exact directory
// revision and the snapshot revision used to authorize the administrator. A
// concurrent change to that authorization snapshot also invalidates the write.
type Store interface {
	directory.Directory
	Create(context.Context, Kind, Document) (Resource, error)
	Replace(context.Context, Kind, string, Document, string) (Resource, error)
	Delete(context.Context, Kind, string, string) error
	Get(context.Context, Kind, string) (Resource, error)
	List(context.Context, Kind, int, int) (Page, error)
	Bindings(context.Context) (BindingSnapshot, error)
	Rebind(ctx context.Context, actor, alias, id string, expected uint64, authorizationRevision directory.Revision) error
	Audit(context.Context) ([]AuditEvent, error)
	Close() error
}

// Text reads a canonical string attribute. Validation belongs to the adapter.
func (d Document) Text(key string) string {
	var s string
	_ = json.Unmarshal(d[key], &s)
	return s
}

// UserFacts projects only fields consumed by authorization. An omitted active
// attribute defaults to true, matching static inventory; null is rejected at
// the provisioning boundary. Groups are resolved separately by the store.
func (d Document) UserFacts() (directory.User, error) {
	u := directory.User{ID: d.Text("externalId"), UserName: d.Text("userName"), UserType: d.Text("userType"), Active: true}
	if u.ID == "" || u.UserName == "" {
		return directory.User{}, fmt.Errorf("stored user lacks identity")
	}
	if raw, ok := d["active"]; ok {
		var active *bool
		if err := json.Unmarshal(raw, &active); err != nil || active == nil {
			return directory.User{}, fmt.Errorf("stored user has invalid active status")
		}
		u.Active = *active
	}
	var enterprise Document
	_ = json.Unmarshal(d["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"], &enterprise)
	u.Department, u.Organization = enterprise.Text("department"), enterprise.Text("organization")
	return u, nil
}
