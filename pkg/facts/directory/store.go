package directory

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid directory resource")
	ErrNotFound = errors.New("directory resource not found")
	ErrConflict = errors.New("directory uniqueness conflict")
	ErrVersion  = errors.New("directory revision changed")
)

// Metadata is assigned by storage. ID identifies the provisioned user or group;
// it is distinct from the provider's ExternalID used for authentication.
// Version changes on mutations, including membership cleanup after user deletion.
type Metadata struct {
	ID       string
	Version  uint64
	Created  time.Time
	Modified time.Time
}

func (m Metadata) ETag() string { return fmt.Sprintf(`W/"%d"`, m.Version) }

// ManagedUser contains the identity and attributes used by authorization. Active is
// explicit at the storage boundary; the HTTP adapter supplies the SCIM default.
// Group membership is owned by Group, not by the user.
type ManagedUser struct {
	Metadata
	ExternalID   string
	UserName     string
	Active       bool
	UserType     string
	Department   string
	Organization string
}

// Group owns direct user memberships. DisplayName changes affect name selectors;
// the stable resource ID continues to select the same group.
type Group struct {
	Metadata
	ExternalID  string
	DisplayName string
	MemberIDs   []string // Stored user IDs, not provider ExternalIDs.
}

type GroupSummary struct {
	ID          string
	DisplayName string
	ExternalID  string
}

// GroupSnapshot contains current groups from one coherent revision.
type GroupSnapshot struct {
	Revision uint64
	Groups   []GroupSummary
}

// AuditSequence identifies one audit event, independently of directory revisions:
// several events can belong to the same mutation. Zero starts at the beginning.
type AuditSequence uint64

const DefaultAuditLimit = 100
const MaxAuditLimit = 1000

type AuditEvent struct {
	Sequence   AuditSequence
	Revision   uint64
	Time       time.Time
	Actor      string
	Action     string
	ID         string
	Alias      string
	PreviousID string
}

// Store owns directory persistence and all changes to authorization indexes.
// Each mutation commits the user or group, memberships, audit and revision
// together. No database handles or multi-call transaction protocol escape here.
// Get methods return independent snapshots; each List returns a typed slice and
// total count from one snapshot (start is one-based). LookupUser resolves identity,
// memberships and current group facts in a single read. Backend failures stay errors.
//
// Replace/Delete accept an optional resource ETag ("*" requires existence).
// A stale precondition leaves state unchanged.
type Store interface {
	Directory
	UserLister
	CreateUser(context.Context, ManagedUser) (ManagedUser, error)
	ReplaceUser(ctx context.Context, id string, user ManagedUser, match string) (ManagedUser, error)
	DeleteUser(ctx context.Context, id, match string) error
	GetUser(context.Context, string) (ManagedUser, error)
	ListUsers(ctx context.Context, start, count int) ([]ManagedUser, int, error)
	CreateGroup(context.Context, Group) (Group, error)
	ReplaceGroup(ctx context.Context, id string, group Group, match string) (Group, error)
	DeleteGroup(ctx context.Context, id, match string) error
	GetGroup(context.Context, string) (Group, error)
	ListGroups(ctx context.Context, start, count int) ([]Group, int, error)
	Groups(context.Context) (GroupSnapshot, error)
	// Audit returns at most limit events after the exclusive sequence cursor,
	// in sequence order. Zero limit uses DefaultAuditLimit; limits above
	// MaxAuditLimit are invalid. An empty result means the cursor is caught up.
	Audit(ctx context.Context, after AuditSequence, limit int) ([]AuditEvent, error)
	Close() error
}
