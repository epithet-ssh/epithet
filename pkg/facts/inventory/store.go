package inventory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrStorage  = errors.New("managed inventory storage unavailable")
	ErrConflict = errors.New("inventory conflict")
	ErrNotFound = errors.New("inventory record not found")
	ErrToken    = errors.New("invalid, expired, revoked, or used enrollment token")
	ErrVersion  = errors.New("record changed; reload before retrying")
)

const DefaultPageLimit = 100
const MaxPageLimit = 1000

// Store is the inventory management contract, independent of Hosts fact lookup.
// Epithet owns enrollment and review policy; implementations persist host and
// token operations. Enrollment and any token consumption form one
// storage call. Consistency is backend-specific.
//
// Only active records contribute lookup facts or reserve authorization names.
// Active exact names and identical patterns are unique. Overlapping patterns are
// permitted; ambiguity is detected by Hosts.LookupHost. Admission or edits
// violating name/pattern uniqueness return ErrConflict. Realms may be shared
// across records without constraints on their labels or account sets.
//
// Returned records and collections are independent snapshots, including results
// of mutations. Implementations must not retain or modify caller-owned maps or
// slices. Nil accounts mean unrestricted; an empty non-nil slice means no accounts.
// Storage failures return errors matching ErrStorage, never missing records.
// Validation errors have no sentinel unless a method specifies one below.
// Contexts bound reads and mutations. The caller owns the store's lifetime;
// HTTP handlers never close it. Callers construct audit events before storage,
// supplying the authenticated actor, action, resource and operation timestamp.
// Storage preserves all event fields. Callers also assign IDs
// before creation using NewID; collisions return ErrConflict. Mutation timestamps
// use event.At. Storage never generates IDs or completes audit events.
// Version is an opaque, backend-owned token, compared only for equality. Stores
// without versioning return empty Host.Version and receive empty expectedVersion.
// Empty expectedVersion means no requested version check; enforcement and
// consistency are backend properties.
type Store interface {
	// SupportsVersioning is stable for the store's lifetime. When true, returned
	// hosts have nonempty versions that change on mutation. HTTP exposes them as
	// ETags. When false, versions and mutation preconditions are empty.
	SupportsVersioning() bool

	// CreateHost persists a new host with the supplied ID and status. It assigns
	// a version according to SupportsVersioning and uses event.At for timestamps.
	// Duplicate IDs return ErrConflict. Epithet chooses pending or active before
	// calling storage.
	CreateHost(ctx context.Context, id string, host Host, event AuditEvent) (*Host, error)
	// ReplaceHost persists the supplied facts and status. It does not enforce
	// enrollment/review workflow rules. ID and timestamps must be echoed unchanged;
	// expectedVersion is the optional concurrency precondition, independent of the
	// supplied Host.Version. Storage owns the new version and update time.
	ReplaceHost(ctx context.Context, host Host, expectedVersion string, event AuditEvent) (*Host, error)
	// Removal retains audit history and appends the supplied event. A missing ID
	// returns ErrNotFound; a failed version precondition returns ErrVersion.
	RemoveHost(ctx context.Context, id string, expectedVersion string, event AuditEvent) error
	// GetHost returns ErrNotFound for an absent ID.
	GetHost(ctx context.Context, id string) (*Host, error)
	// ListHosts returns hosts ordered by ID, strictly after the cursor.
	// Empty after starts a read; nonempty after is a full resource ID. Zero limit
	// defaults to 100; negative limits and limits above 1,000 are invalid. Pending
	// filters host records before applying the limit. A short page ends that read.
	// Each page is independent; later calls may observe changes.
	ListHosts(ctx context.Context, after string, limit int, pending bool) ([]Host, error)
	// EnrollHost creates a host at the client-selected ID. Epithet supplies pending
	// for a submission awaiting review, or active for single-use preapproval;
	// active creation must validate and consume the token whose secret is id.
	// An identical retry returns the existing host without changing its status,
	// version, timestamps, or audit. Enrollment never edits existing host facts.
	// Different facts at the same ID return ErrConflict (pending) or ErrToken
	// (preapproved). Token validation, creation, and audit are one storage call;
	// consistency remains a backend property.
	EnrollHost(ctx context.Context, id string, host Host, event AuditEvent) (*Host, error)
	// CreateToken stores a single-use credential without creating a host.
	// Its supplied ID becomes the host ID on enrollment. Lifetime must be
	// positive and at most 24 hours.
	CreateToken(ctx context.Context, id string, lifetime time.Duration, event AuditEvent) (EnrollmentToken, error)
	// RevokeToken prevents unused credentials from authorizing enrollment.
	RevokeToken(ctx context.Context, id string, event AuditEvent) error
	// Audit returns events and a backend-owned continuation cursor. Empty input
	// starts a read; empty next completes it. Callers forward cursors unchanged.
	// Ordering, visibility and cursor lifetime belong to the backend. Timestamps
	// need not be unique or monotonic. Zero limit defaults to 100; maximum 1,000.
	Audit(ctx context.Context, cursor string, limit int) (events []AuditEvent, next string, err error)
}

// EnrollmentToken's ID is also its secret and the resulting host ID.
// Unused tokens retain an empty UsedBy value.
type EnrollmentToken struct {
	ID        string    `yaml:"id"`
	ExpiresAt time.Time `yaml:"expires-at"`
	UsedBy    string    `yaml:"used-by,omitempty"`
	Revoked   bool      `yaml:"revoked"`
}

// AuditEvent is supplied by the caller alongside a mutation. Storage preserves
// every field, including the supplied timestamp.
type AuditEvent struct {
	At       time.Time `yaml:"at"`
	Actor    string    `yaml:"actor"`
	Action   string    `yaml:"action"`
	Resource string    `yaml:"resource"`
}

// NewAuditEvent describes an operation using the actor authenticated by the caller.
// The caller selects the resource ID before constructing the event.
func NewAuditEvent(actor, action, resource string) AuditEvent {
	return AuditEvent{At: time.Now().UTC(), Actor: actor, Action: action, Resource: resource}
}

// NewID creates an inventory resource ID or single-use enrollment credential.
func NewID() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
