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
	ErrRevision = errors.New("record changed; reload before retrying")
)

const DefaultPageLimit = 100
const MaxPageLimit = 1000

// Store is the inventory management contract, independent of Hosts fact lookup.
// Epithet owns enrollment and review policy; implementations persist host and
// token operations. Each call is independent: token redemption and the following
// host replacement do not share a transaction. Consistency is backend-specific.
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
type Store interface {
	// CreateHost persists a new host with the supplied ID and status. It assigns
	// revision 1 and uses event.At for creation/update timestamps. Duplicate IDs
	// return ErrConflict. Epithet chooses pending or active before calling storage.
	CreateHost(ctx context.Context, id string, host Host, event AuditEvent) (*Host, error)
	// ReplaceHost persists the supplied facts and status. It does not enforce
	// enrollment/review workflow rules. ID and timestamps must be echoed unchanged;
	// the separate revision argument must match the stored nonzero version.
	// Success advances revision/update time. Leaving pending revokes unused tokens.
	ReplaceHost(ctx context.Context, host Host, revision uint64, event AuditEvent) (*Host, error)
	// Removal retains audit history and appends the supplied event. A missing ID
	// returns ErrNotFound; a stale/zero revision returns ErrRevision.
	RemoveHost(ctx context.Context, id string, revision uint64, event AuditEvent) error
	// GetHost returns ErrNotFound for an absent ID.
	GetHost(ctx context.Context, id string) (*Host, error)
	// ListHosts returns hosts ordered by ID, strictly after the cursor.
	// Empty after starts a read; nonempty after is a full resource ID. Zero limit
	// defaults to 100; negative limits and limits above 1,000 are invalid. Pending
	// filters host records before applying the limit. A short page ends that read.
	// Each page is independent; later calls may observe changes.
	ListHosts(ctx context.Context, after string, limit int, pending bool) ([]Host, error)
	// CreateToken creates an empty pending host reservation. Its supplied ID is
	// also its single-use secret. Lifetime must be positive and at most 24 hours.
	CreateToken(ctx context.Context, id string, lifetime time.Duration, event AuditEvent) (EnrollmentToken, error)
	// RedeemToken consumes an unused, unrevoked, unexpired token and returns its
	// pending host reservation. Invalid credentials return ErrToken. It appends
	// the supplied event but does not change host facts, status, or revision.
	// Consumption is final even if a later ReplaceHost fails.
	RedeemToken(ctx context.Context, id string, event AuditEvent) (*Host, error)
	// RevokeToken records revocation and advances the reservation's resource version.
	RevokeToken(ctx context.Context, id string, event AuditEvent) error
	// Audit returns events and a backend-owned continuation cursor. Empty input
	// starts a read; empty next completes it. Callers forward cursors unchanged.
	// Ordering, visibility and cursor lifetime belong to the backend. Timestamps
	// need not be unique or monotonic. Zero limit defaults to 100; maximum 1,000.
	Audit(ctx context.Context, cursor string, limit int) (events []AuditEvent, next string, err error)
}

// EnrollmentToken's ID is also its secret. UsedBy is the reserved host ID after
// consumption; it does not imply that the host update succeeded. Unused tokens
// retain an empty UsedBy value.
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

// NewID creates an inventory resource ID. A token reservation also uses this
// cryptographically random value as its enrollment credential.
func NewID() string {
	var b [32]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
