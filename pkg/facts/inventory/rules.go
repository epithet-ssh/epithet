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

// CheckVersion compares opaque versions. Empty means no requested version check;
// the backend determines the consistency of checking and applying a mutation.
func CheckVersion(current Host, expectedVersion string) error {
	if expectedVersion != "" && current.Version != expectedVersion {
		return ErrVersion
	}
	return nil
}

// Review validates an administrator edit or review at the Epithet boundary.
// A review cannot also edit the facts being approved. Storage accepts complete
// replacements, without imposing the administrator review workflow.
func Review(current, proposed Host, expectedVersion string, now time.Time) (Host, string, error) {
	fail := func(err error) (Host, string, error) { return Host{}, "", err }
	if err := CheckVersion(current, expectedVersion); err != nil {
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
		if !SameHostFacts(current, proposed) {
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
	proposed.Version = current.Version
	proposed.UpdatedAt = now
	return proposed, action, nil
}

// SameHostFacts compares enrollment facts without lifecycle metadata.
func SameHostFacts(a, b Host) bool {
	a.ID = ""
	a.Status = ""
	a.Version = ""
	a.CreatedAt = time.Time{}
	a.UpdatedAt = time.Time{}
	b.ID = ""
	b.Status = ""
	b.Version = ""
	b.CreatedAt = time.Time{}
	b.UpdatedAt = time.Time{}
	return reflect.DeepEqual(a, b)
}

// Enroll validates a PUT enrollment before one storage operation. A preapproval
// token is the host ID; the control-plane pending-enrollment bearer never enters
// this layer. An identical retry does not update the existing host.
func Enroll(ctx context.Context, store Store, id string, host Host, token string, event AuditEvent) (*Host, error) {
	host = cloneHost(host)
	if id == "" {
		return nil, fmt.Errorf("host id is required")
	}
	for _, name := range host.Names {
		if strings.ContainsAny(name, "*?") {
			return nil, fmt.Errorf("enrollment requires exact hostnames")
		}
	}
	if err := host.Validate(); err != nil {
		return nil, err
	}
	host.Status = StatusPending
	if token != "" {
		if token != id {
			return nil, ErrToken
		}
		host.Status = StatusActive
	}
	host.ID = id
	return store.UpsertHost(ctx, host, WriteConditions{CreateOnly: true, ConsumeToken: token != ""}, event)
}

// Creation prepares storage metadata without deciding the host's status.
func Creation(id string, host Host, now time.Time) (Host, error) {
	host = cloneHost(host)
	if err := validateStoredHost(&host); err != nil {
		return Host{}, err
	}
	host.ID, host.Version, host.CreatedAt, host.UpdatedAt = id, "", now, now
	return host, nil
}

// Replacement checks resource metadata and prepares a complete host write.
// Review policy belongs to Review, not this storage operation.
func Replacement(current, proposed Host, expectedVersion string, now time.Time) (Host, error) {
	if err := CheckVersion(current, expectedVersion); err != nil {
		return Host{}, err
	}
	if proposed.ID != current.ID || !proposed.CreatedAt.Equal(current.CreatedAt) || !proposed.UpdatedAt.Equal(current.UpdatedAt) {
		return Host{}, fmt.Errorf("id, createdAt and updatedAt are server-owned")
	}
	proposed = cloneHost(proposed)
	if err := validateStoredHost(&proposed); err != nil {
		return Host{}, err
	}
	proposed.Version, proposed.UpdatedAt = current.Version, now
	return proposed, nil
}

func validateStoredHost(host *Host) error {
	switch host.Status {
	case StatusPending, StatusDenied, StatusActive:
	default:
		return fmt.Errorf("invalid host status %q", host.Status)
	}
	return host.Validate()
}

// Validation normalizes/sorts names. Copy collections before planning so failed
// operations cannot alter a caller's fields or current snapshot.
func cloneHost(p Host) Host {
	p.Names = slices.Clone(p.Names)
	p.Labels = maps.Clone(p.Labels)
	p.Accounts = slices.Clone(p.Accounts)
	return p
}
