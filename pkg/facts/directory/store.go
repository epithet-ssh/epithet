package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/writ/object"
)

var (
	ErrInvalid  = errors.New("invalid directory resource")
	ErrNotFound = errors.New("directory resource not found")
	ErrConflict = errors.New("directory uniqueness conflict")
	ErrVersion  = errors.New("directory revision changed")
)

// Metadata describes a provisioned user or group. User IDs are supplied by
// Epithet after identity mapping; Epithet generates group IDs before storage.
// The caller supplies Created and Modified. Storage retains Created on replacement,
// preserves the supplied Modified, and owns Version for both resource types.
// Version is empty when Store.SupportsVersioning is false. Otherwise it is a
// nonempty opaque token, compared only for equality, that changes on mutations
// including membership cleanup after user deletion.
type Metadata struct {
	ID       string
	Version  string
	Created  time.Time
	Modified time.Time
}

// ManagedUser contains the identity and attributes used by authorization. Active is
// explicit at the storage boundary; the HTTP adapter supplies the SCIM default.
// Group membership is owned by ManagedGroup, not by the user.
type ManagedUser struct {
	Metadata
	ExternalID   string
	UserName     string
	Active       bool
	UserType     string
	Department   string
	Organization string
}

// Validate checks input-only user constraints before creation or replacement,
// without changing the record. ID must already be assigned by the caller.
// Storage owns uniqueness, existence and version checks against current state.
func (u ManagedUser) Validate() error {
	if strings.TrimSpace(u.ID) == "" || strings.TrimSpace(u.UserName) == "" {
		return fmt.Errorf("%w: ID and userName are required", ErrInvalid)
	}
	return nil
}

// ManagedGroup owns direct user memberships. DisplayName changes affect name selectors;
// the stable resource ID continues to select the same group.
type ManagedGroup struct {
	Metadata
	ExternalID  string
	DisplayName string
	MemberIDs   []string // Distinct stored user IDs, not provider ExternalIDs; callers deduplicate before writing.
}

// Group returns the authorization facts for this managed group. DisplayName
// becomes its name and a nonempty ExternalID becomes the externalId attribute.
// MemberIDs, Version, Created and Modified are omitted from the result.
func (g ManagedGroup) Group() Group {
	group := Group{ID: g.ID, Names: []string{g.DisplayName}}
	if g.ExternalID != "" {
		group.Attributes = object.Attributes{"externalId": {g.ExternalID}}
	}
	return group
}

// Validate checks input-only group constraints before creation or replacement,
// without changing the record. ID must already be assigned by the caller.
// Storage handles checks that depend on existing records.
func (g ManagedGroup) Validate() error {
	if strings.TrimSpace(g.ID) == "" || strings.TrimSpace(g.DisplayName) == "" {
		return fmt.Errorf("%w: ID and displayName are required", ErrInvalid)
	}
	return nil
}

const DefaultAuditLimit = 100
const MaxAuditLimit = 1000

// AuditEvent describes a mutation. Callers supply the event alongside the write;
// storage preserves all of its fields.
type AuditEvent struct {
	Time       time.Time
	Actor      string
	Action     string
	ID         string
	Alias      string
	PreviousID string
}

// NewAuditEvent constructs an event above storage using the authenticated actor.
// The caller supplies the action and resource ID; the timestamp records this operation.
func NewAuditEvent(ctx context.Context, action, id string) AuditEvent {
	return AuditEvent{Time: time.Now().UTC(), Actor: Actor(ctx), Action: action, ID: id}
}

// Store is the directory management contract, independent of Directory fact
// lookup. Each method describes a complete directory operation. Implementations
// own persistence and authorization indexes. Consistency, concurrent access,
// propagation timing and failure atomicity are backend properties, not guarantees
// of this interface. An error does not establish whether a write took effect.
//
// Callers validate users and groups before writing; stores may assume valid
// input attributes. Indexes and derived storage values stay private to backends.
// Creation preserves the supplied ID for users and groups. IDs are unique across
// both resource types; a collision returns ErrConflict without replacing anything.
// Creation preserves supplied Created and Modified (including zero). Storage
// ignores caller-supplied Version: it assigns a token when versioning is supported,
// or leaves Version empty otherwise. Replacement selects the record by its ID,
// retains stored Created, preserves supplied Modified, and follows the same
// versioning capability, changing the token when supported.
// Each mutation receives an audit event constructed by the caller. Storage
// persists the supplied event with the mutation;
// it does not derive the event's actor, action, ID or time. Audit history survives
// resource deletion. Backend failures remain errors, never absent resources.
//
// Replace/Delete receive expectedVersion from the caller; enforcement is
// backend-specific. Callers pass empty when SupportsVersioning is false.
// Empty means no requested version check. The SCIM adapter interprets HTTP
// conditional headers. Replacement never creates a resource.
//
// Contexts bound reads and mutations. The caller
// owns implementation lifetime; closing it is not a management operation.
type Store interface {
	// SupportsVersioning declares whether users and groups have resource versions
	// usable for conditional writes. False means empty Metadata.Version and
	// callers pass empty expectedVersion. This capability is stable for the store's
	// lifetime; SCIM uses it to advertise ETag support. Backend consistency and
	// atomicity remain implementation properties.
	SupportsVersioning() bool

	// SupportsPatchUser and SupportsPatchGroup declare support for partial updates
	// to each resource type, including add, remove and replace operations. They
	// describe backend capabilities, not authorization for an individual request.
	// Values must remain stable for the lifetime of the store. The SCIM adapter
	// uses them for discovery and rejects PATCH for an unsupported resource type.
	SupportsPatchUser() bool
	SupportsPatchGroup() bool

	// CreateUser creates and returns a user with the supplied ID, preserving the
	// supplied Created and Modified timestamps. Version follows SupportsVersioning.
	// Epithet resolves identity before calling storage;
	// the store does not interpret SCIM attributes or OIDC claims.
	// IDs are unique by exact value. User names are unique under Unicode NFKC
	// normalization followed by case folding. Collisions return
	// ErrConflict, including collisions with inactive users. Preserve supplied
	// spelling and Active (there is no default at this boundary). ExternalID is
	// optional and need not be unique. A duplicate ID must never replace a user.
	// The new user has no memberships until a group adds its resource ID.
	CreateUser(context.Context, ManagedUser, AuditEvent) (ManagedUser, error)

	// ReplaceUser fully replaces the user selected by user.ID and returns
	// the updated user. Apply CreateUser's uniqueness rules,
	// excluding this user's existing values; omitted attributes become zero values.
	// ExternalID may change without changing the resource ID or group memberships.
	// ID selects the record; Modified is preserved. Supplied Created and Version
	// are ignored; retain the stored Created. Version follows SupportsVersioning.
	// Return ErrNotFound if absent or ErrConflict for a uniqueness violation.
	// Preserve memberships. Version handling follows the backend's semantics.
	ReplaceUser(ctx context.Context, user ManagedUser, expectedVersion string, event AuditEvent) (ManagedUser, error)

	// DeleteUser deletes the user and removes it from every group.
	// Each affected group gets the supplied modified timestamp and, when versioning
	// is supported, a new Version; group IDs and other attributes are retained. Release
	// the user's unique UserName. Return ErrNotFound if absent.
	// Version handling and visibility of membership cleanup follow the backend's
	// semantics. Persist the supplied audit event.
	DeleteUser(ctx context.Context, id, expectedVersion string, modified time.Time, event AuditEvent) error

	// GetUser returns the provisioning record, including metadata and inactive
	// users, selected by resource ID. Return nil, nil if absent. No state changes;
	// Directory.LookupUser uses the same ID to return facts.
	GetUser(context.Context, string) (*ManagedUser, error)

	// ListUsers returns a page of provisioning records, including inactive users,
	// in backend-defined order, plus the total user count before pagination. start
	// is one-based and must be at least 1; count must be nonnegative. Zero count
	// returns an empty page and the total, not a default page size. Invalid paging
	// arguments return an error. A start beyond the end returns an empty page.
	// Empty pages may be nil. Read consistency is backend-specific.
	ListUsers(ctx context.Context, start, count int) ([]ManagedUser, int, error)

	// CreateGroup creates and returns a group, preserving supplied ID, Created and
	// Modified. Version follows SupportsVersioning. An ID collision with any existing
	// user or group returns ErrConflict; creation never replaces a resource.
	// Preserve DisplayName spelling. DisplayName and ExternalID need not be unique;
	// ExternalID is optional. MemberIDs must reference existing user resource IDs (inactive
	// users are allowed); missing users or group references return ErrInvalid.
	// Callers deduplicate MemberIDs before writing; storage need not normalize
	// duplicate input. MemberIDs order is unspecified.
	// Nil and empty MemberIDs both mean no members.
	CreateGroup(context.Context, ManagedGroup, AuditEvent) (ManagedGroup, error)

	// ReplaceGroup fully replaces the group selected by group.ID, including its
	// complete membership set, and returns the updated group. Apply CreateGroup's
	// membership checks; nil/empty MemberIDs remove all members.
	// ID selects the record; Modified is preserved. Supplied Created and Version
	// are ignored; retain the stored Created. Version follows SupportsVersioning.
	// A rename changes group-name authorization facts without changing the resource
	// ID. Return ErrNotFound if absent or ErrInvalid for missing members.
	// Version handling follows the backend's semantics.
	ReplaceGroup(ctx context.Context, group ManagedGroup, expectedVersion string, event AuditEvent) (ManagedGroup, error)

	// DeleteGroup deletes the group and its memberships, leaving member users
	// intact. The group is removed from their authorization facts according to the
	// backend's propagation semantics. Return ErrNotFound if absent.
	// Persist the supplied audit event. Version handling is backend-specific.
	DeleteGroup(ctx context.Context, id, expectedVersion string, event AuditEvent) error

	// GetGroup returns the group selected by resource ID, with metadata and its
	// complete, distinct MemberIDs in unspecified order. An empty group's
	// membership slice may be nil. Return nil, nil if absent. Reading
	// the group does not change state.
	GetGroup(context.Context, string) (*ManagedGroup, error)

	// ListGroups returns a page of complete groups in backend-defined order, plus
	// the total group count before pagination. start is one-based and must be at
	// least 1; count must be nonnegative. Zero count returns an empty page and the
	// total, not a default page size. Invalid paging arguments return an error;
	// a start beyond the end returns an empty page, which may be nil. Memberships follow
	// GetGroup's semantics. Read consistency is backend-specific.
	ListGroups(ctx context.Context, start, count int) ([]ManagedGroup, int, error)

	// Audit returns at most limit events and a backend-owned continuation cursor.
	// Empty cursor starts a read; pass next back unchanged to continue. Empty next
	// means no further page is available. Cursors are scoped to this backend.
	// Ordering, consistency during writes, and cursor lifetime are backend
	// properties; timestamps need not be unique or monotonic.
	// Zero limit uses DefaultAuditLimit; negative limits or limits above
	// MaxAuditLimit return ErrInvalid. Empty pages may be nil.
	// Events retain their supplied timestamps and survive resource deletion.
	Audit(ctx context.Context, cursor string, limit int) (events []AuditEvent, next string, err error)
}

// WithActor attaches the identity authenticated by the service boundary. HTTP
// payloads must never supply it. NewAuditEvent reads it before calling storage.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

type actorKey struct{}

// Actor returns the trusted actor, retaining "scim" for direct provisioning
// callers without a human identity (including imports and shared-secret calls).
func Actor(ctx context.Context) string {
	actor, _ := ctx.Value(actorKey{}).(string)
	if actor == "" {
		return "scim"
	}
	return actor
}
