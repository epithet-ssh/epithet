package inventory

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"
)

// CheckRevision must run against the snapshot being mutated, inside the backend's
// transaction or conditional commit. A stale or missing version never writes.
func CheckRevision(current Host, version uint64) error {
	if version == 0 || current.Revision != version {
		return ErrRevision
	}
	return nil
}

// Review validates an administrator edit or review at the Epithet boundary.
// A review cannot also edit the facts being approved. Storage accepts complete
// replacements, including enrollment filling and activating a reservation.
func Review(current, proposed Host, version uint64, now time.Time) (Host, string, error) {
	fail := func(err error) (Host, string, error) { return Host{}, "", err }
	if err := CheckRevision(current, version); err != nil {
		return fail(err)
	}
	if proposed.ID != current.ID || !proposed.CreatedAt.Equal(current.CreatedAt) || !proposed.UpdatedAt.Equal(current.UpdatedAt) {
		return fail(fmt.Errorf("id, createdAt and updatedAt are server-owned"))
	}
	proposed = cloneHost(proposed)
	action := "edit"
	if proposed.Status != current.Status {
		if current.Status != StatusPending {
			return fail(fmt.Errorf("only pending records can be reviewed"))
		}
		if !sameHostFacts(current, proposed) {
			return fail(fmt.Errorf("edit the host before changing its status"))
		}
		switch proposed.Status {
		case StatusActive:
			action = "approve"
			if err := proposed.Validate(); err != nil {
				return fail(fmt.Errorf("host attributes are required before approval: %w", err))
			}
		case StatusDenied:
			action = "deny"
		default:
			return fail(fmt.Errorf("pending records may only become active or denied"))
		}
	} else {
		if current.Status != StatusPending && current.Status != StatusActive {
			return fail(fmt.Errorf("only pending or active records can be edited"))
		}
		if err := proposed.Validate(); err != nil {
			return fail(err)
		}
	}
	proposed.Revision = current.Revision + 1
	proposed.UpdatedAt = now
	return proposed, action, nil
}

// EmptyHost identifies a reservation without host facts.
func EmptyHost(p Host) bool {
	return p.Names == nil && p.Labels == nil && p.Accounts == nil && p.PrincipalMode == "" && p.Realm == ""
}

func sameHostFacts(a, b Host) bool {
	a.ID = ""
	a.Status = ""
	a.Revision = 0
	a.CreatedAt = time.Time{}
	a.UpdatedAt = time.Time{}
	b.ID = ""
	b.Status = ""
	b.Revision = 0
	b.CreatedAt = time.Time{}
	b.UpdatedAt = time.Time{}
	return reflect.DeepEqual(a, b)
}

// Enroll performs Epithet's enrollment workflow using independent storage calls.
// Validation precedes token consumption. A redeemed token stays consumed if the
// subsequent reservation update fails.
func Enroll(ctx context.Context, store Store, id string, host Host, token string, event AuditEvent) (*Host, error) {
	host = cloneHost(host)
	for _, name := range host.Names {
		if strings.ContainsAny(name, "*?") {
			return nil, fmt.Errorf("enrollment requires exact hostnames")
		}
	}
	if err := host.Validate(); err != nil {
		return nil, err
	}
	if token == "" {
		pending, err := store.ListHosts(ctx, "", MaxPageLimit, true)
		if err != nil {
			return nil, err
		}
		if len(pending) >= 1000 {
			return nil, fmt.Errorf("pending enrollment queue is full")
		}
		host.Status = StatusPending
		return store.CreateHost(ctx, id, host, event)
	}
	redeemed := event
	redeemed.Action = "token-redeem"
	reserved, err := store.RedeemToken(ctx, token, redeemed)
	if err != nil {
		return nil, err
	}
	host.ID, host.Revision = reserved.ID, reserved.Revision
	host.CreatedAt, host.UpdatedAt = reserved.CreatedAt, reserved.UpdatedAt
	host.Status = StatusActive
	return store.ReplaceHost(ctx, host, reserved.Revision, event)
}

// Creation prepares storage metadata without deciding the host's status.
func Creation(id string, host Host, now time.Time) (Host, error) {
	host = cloneHost(host)
	if err := validateStoredHost(&host); err != nil {
		return Host{}, err
	}
	host.ID, host.Revision, host.CreatedAt, host.UpdatedAt = id, 1, now, now
	return host, nil
}

// Replacement checks resource metadata and prepares a complete host write.
// Review policy belongs to Review, not this storage operation.
func Replacement(current, proposed Host, version uint64, now time.Time) (Host, error) {
	if err := CheckRevision(current, version); err != nil {
		return Host{}, err
	}
	if proposed.ID != current.ID || !proposed.CreatedAt.Equal(current.CreatedAt) || !proposed.UpdatedAt.Equal(current.UpdatedAt) {
		return Host{}, fmt.Errorf("id, createdAt and updatedAt are server-owned")
	}
	proposed = cloneHost(proposed)
	if err := validateStoredHost(&proposed); err != nil {
		return Host{}, err
	}
	proposed.Revision, proposed.UpdatedAt = current.Revision+1, now
	return proposed, nil
}

func validateStoredHost(host *Host) error {
	switch host.Status {
	case StatusPending, StatusDenied:
		if EmptyHost(*host) {
			return nil
		}
	case StatusActive:
	default:
		return fmt.Errorf("invalid host status %q", host.Status)
	}
	return host.Validate()
}

// Reservation constructs the empty record and expiring single-use credential
// which the backend persists together. IDs/secrets are supplied by Epithet.
func Reservation(id string, lifetime time.Duration, now time.Time) (Host, EnrollmentToken, error) {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return Host{}, EnrollmentToken{}, fmt.Errorf("token lifetime must be positive and no more than 24h")
	}
	return Host{ID: id, Revision: 1, Status: StatusPending, CreatedAt: now, UpdatedAt: now}, EnrollmentToken{ID: id, ExpiresAt: now.Add(lifetime)}, nil
}

// Validation normalizes/sorts names. Copy collections before planning so failed
// operations cannot alter a caller's fields or current snapshot.
func cloneHost(p Host) Host {
	p.Names = slices.Clone(p.Names)
	p.Labels = maps.Clone(p.Labels)
	p.Accounts = slices.Clone(p.Accounts)
	return p
}
