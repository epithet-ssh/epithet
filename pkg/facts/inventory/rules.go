package inventory

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
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

// ValidateEdit checks an administrator edit, retaining server-owned metadata.
func (proposed *Host) ValidateEdit(current Host, expectedVersion string) error {
	if err := CheckVersion(current, expectedVersion); err != nil {
		return err
	}
	if proposed.ID != current.ID || !proposed.CreatedAt.Equal(current.CreatedAt) || !proposed.UpdatedAt.Equal(current.UpdatedAt) {
		return fmt.Errorf("id, createdAt and updatedAt are server-owned")
	}
	if proposed.Status != StatusActive || current.Status != StatusActive {
		return fmt.Errorf("only active records can be edited")
	}
	proposed.Names = slices.Clone(proposed.Names)
	return proposed.Validate()
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

// CreateHost validates and commits an authorized active-host creation. Identical
// retries preserve the record and its audit history; differing facts conflict
// atomically in storage.
func CreateHost(ctx context.Context, store Store, id string, host Host, event AuditEvent) (*Host, error) {
	if id == "" {
		return nil, fmt.Errorf("host id is required")
	}
	host = cloneHost(host)
	if err := host.Validate(); err != nil {
		return nil, err
	}
	host.ID, host.Status = id, StatusActive
	return store.UpsertHost(ctx, host, WriteConditions{CreateOnly: true}, event)
}

// Creation validates an active host and prepares its storage metadata.
func Creation(id string, host Host, now time.Time) (Host, error) {
	host = cloneHost(host)
	if host.Status != StatusActive {
		return Host{}, fmt.Errorf("invalid host status %q", host.Status)
	}
	if err := host.Validate(); err != nil {
		return Host{}, err
	}
	host.ID, host.Version, host.CreatedAt, host.UpdatedAt = id, "", now, now
	return host, nil
}

// Replacement checks resource metadata and prepares a complete host write.
// Host.ValidateEdit owns the validation shared with the HTTP boundary.
func Replacement(current, proposed Host, expectedVersion string, now time.Time) (Host, error) {
	if err := proposed.ValidateEdit(current, expectedVersion); err != nil {
		return Host{}, err
	}
	proposed = cloneHost(proposed)
	proposed.Version, proposed.UpdatedAt = current.Version, now
	return proposed, nil
}

// Copy collections so a prepared write is independent of the caller's snapshot.
func cloneHost(p Host) Host {
	p.Names = slices.Clone(p.Names)
	p.Labels = maps.Clone(p.Labels)
	p.Accounts = slices.Clone(p.Accounts)
	return p
}
