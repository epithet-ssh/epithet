package inventory

import (
	"context"
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

// AuditSequence identifies one committed event independently of its timestamp.
// Sequences increase and are never reused, including after record deletion.
type AuditSequence uint64

// Store owns managed inventory persistence and admission. Each mutation commits
// the record, token changes, audit event, and inventory revision atomically.
// Active exact names and patterns are unique; shared named realms require equal
// labels and account sets, and generated realms belong to one host. Pending and
// denied records never contribute lookup facts or reserve authorization names.
// Implementations enforce these rules in storage, without relying on coordination
// between service processes. Database handles and transaction steps stay private.
//
// Reads return independent, coherent snapshots. LookupHost returns an opaque
// revision from the same snapshot as its facts; exact names take precedence, and
// multiple matching active patterns return ErrConflict. Storage failures return
// ErrStorage, never missing records. Contexts bound both reads and mutations.
// The caller owns the store's lifetime; HTTP handlers never close it.
type Store interface {
	Hosts

	// Enroll validates a proposal and creates a pending record without a token.
	// A valid token atomically activates its reserved record and consumes the
	// preapproval. Expired, revoked, or used tokens return ErrToken.
	Enroll(ctx context.Context, proposal Proposal, token string) (*HostRecord, error)
	// AddPattern validates and admits an active pattern as one audited mutation.
	AddPattern(ctx context.Context, actor string, proposal Proposal) (*HostRecord, error)
	// Change accepts edit, approve, deny, or remove. The expected record revision
	// must be nonzero and current, otherwise ErrRevision leaves state unchanged.
	// Edit requires a proposal; approve and deny require a pending record. Moving
	// a record out of pending revokes unused preapproval. Remove returns nil and
	// deletes the record, its token, and its audit history.
	Change(ctx context.Context, actor, action, id string, revision uint64, proposal *Proposal) (*HostRecord, error)
	Get(ctx context.Context, id string) (*HostRecord, error)
	// List returns at most limit records after the exclusive full-ID cursor,
	// ordered by ID. pending restricts results before applying the limit.
	// Empty after starts at the beginning. Zero limit uses DefaultPageLimit;
	// negative limits or limits above MaxPageLimit are invalid. An empty page
	// ends enumeration. A short page means no further matching records exist in
	// that snapshot. Each page is coherent; separate pages may see changes.
	List(ctx context.Context, after string, limit int, pending bool) ([]HostRecord, error)
	// CreateToken reserves an empty pending record for single-use preapproval.
	// Lifetime must be positive and no more than 24 hours. The token's ID is the
	// reserved host ID; redemption preserves its creation time.
	CreateToken(ctx context.Context, actor string, lifetime time.Duration) (EnrollmentToken, error)
	// Tokens includes used, revoked, and expired tokens, ordered by ID, with
	// the same exclusive full-ID cursor and page limits as List.
	Tokens(ctx context.Context, after string, limit int) ([]EnrollmentToken, error)
	RevokeToken(ctx context.Context, actor, id string) error
	// Audit returns at most limit surviving events after the exclusive sequence
	// cursor, in sequence order. Zero after starts at the beginning. Page limits
	// are the same as List; an empty page means the reader is caught up.
	Audit(ctx context.Context, after AuditSequence, limit int) ([]AuditEvent, error)
	Close() error
}

// HostRecord includes the editable proposal and server-owned admission metadata.
// IDs are 64 lowercase hexadecimal characters; revisions increase on mutations.
type HostRecord struct {
	ID        string    `yaml:"id"`
	Revision  uint64    `yaml:"revision"`
	Status    string    `yaml:"status"`
	Proposal  Proposal  `yaml:"host,omitempty"`
	CreatedAt time.Time `yaml:"created-at"`
	UpdatedAt time.Time `yaml:"updated-at"`
}

// EnrollmentToken's ID is also its secret. UsedBy is the reserved host ID after
// redemption; unused tokens retain an empty UsedBy value.
type EnrollmentToken struct {
	ID        string    `yaml:"id"`
	ExpiresAt time.Time `yaml:"expires-at"`
	UsedBy    string    `yaml:"used-by,omitempty"`
	Revoked   bool      `yaml:"revoked"`
}

type AuditEvent struct {
	Sequence AuditSequence `yaml:"sequence"`
	At       time.Time     `yaml:"at"`
	Actor    string        `yaml:"actor"`
	Action   string        `yaml:"action"`
	Resource string        `yaml:"resource"`
}
