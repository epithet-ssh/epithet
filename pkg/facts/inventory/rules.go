package inventory

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/epithet-ssh/epithet/pkg/principal"
)

// CheckRevision must run against the snapshot being mutated, inside the backend's
// transaction or conditional commit. A stale or missing version never writes.
func CheckRevision(current HostRecord, version uint64) error {
	if version == 0 || current.Revision != version {
		return ErrRevision
	}
	return nil
}

// Replacement plans one edit or review. It has no storage side effects. Backends
// atomically check active-name/realm conflicts and persist this record, any token
// revocation, and its audit event. It deliberately cannot combine edit and review.
func Replacement(current, proposed HostRecord, version uint64, now time.Time) (HostRecord, string, error) {
	fail := func(err error) (HostRecord, string, error) { return HostRecord{}, "", err }
	if err := CheckRevision(current, version); err != nil {
		return fail(err)
	}
	if proposed.ID != current.ID || !proposed.CreatedAt.Equal(current.CreatedAt) || !proposed.UpdatedAt.Equal(current.UpdatedAt) {
		return fail(fmt.Errorf("id, createdAt and updatedAt are server-owned"))
	}
	proposed.Proposal = cloneProposal(proposed.Proposal)
	action := "edit"
	if proposed.Status != current.Status {
		if current.Status != "pending" {
			return fail(fmt.Errorf("only pending records can be reviewed"))
		}
		if !reflect.DeepEqual(current.Proposal, proposed.Proposal) {
			return fail(fmt.Errorf("edit the host before changing its status"))
		}
		switch proposed.Status {
		case "active":
			action = "approve"
			if err := proposed.Proposal.Validate(); err != nil {
				return fail(fmt.Errorf("host attributes are required before approval: %w", err))
			}
		case "denied":
			action = "deny"
		default:
			return fail(fmt.Errorf("pending records may only become active or denied"))
		}
	} else {
		if current.Status != "pending" && current.Status != "active" {
			return fail(fmt.Errorf("only pending or active records can be edited"))
		}
		if err := proposed.Proposal.Validate(); err != nil {
			return fail(err)
		}
	}
	proposed.Revision = current.Revision + 1
	proposed.UpdatedAt = now
	return proposed, action, nil
}

// EmptyProposal identifies a reservation without host attributes. Only non-active
// records associated with enrollment metadata may have this shape.
func EmptyProposal(p Proposal) bool {
	return p.Names == nil && p.Pattern == "" && p.Labels == nil && p.Accounts == nil && p.PrincipalMode == "" && p.Realm == ""
}

// canRedeem is checked and consumed in the same atomic mutation as admission.
func canRedeem(reserved HostRecord, token *EnrollmentToken, now time.Time) bool {
	return reserved.Status == "pending" && token != nil && token.ID == reserved.ID && !token.Revoked && token.UsedBy == "" && now.Before(token.ExpiresAt)
}

// CheckRealm compares a candidate with an active member. Backends select all
// active members of the candidate's realm and prevent concurrent admissions from
// invalidating these checks. Generated realms identify one host; named realms
// require equal authorization attributes, regardless of account ordering.
func CheckRealm(candidate Proposal, member HostRecord) error {
	if member.Status != "active" || candidate.Realm == "" || candidate.Realm != member.Proposal.Realm {
		return nil
	}
	if principal.Realm(candidate.Realm).IsGeneratedHost() {
		return fmt.Errorf("%w: principal realm is already active on host %s", ErrConflict, member.ID)
	}
	a, b := candidate.Accounts, member.Proposal.Accounts
	if !maps.Equal(candidate.Labels, member.Proposal.Labels) || (a == nil) != (b == nil) {
		return fmt.Errorf("%w: realm %q has different authorization attributes from host %s", ErrConflict, candidate.Realm, member.ID)
	}
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	if !slices.Equal(a, b) {
		return fmt.Errorf("%w: realm %q has different authorization attributes from host %s", ErrConflict, candidate.Realm, member.ID)
	}
	return nil
}

// MutationEvent gives every backend the same audit vocabulary. Removal deletes
// the record's audit history and therefore does not append an event.
func MutationEvent(id, actor, action string, now time.Time) *AuditEvent {
	if action == "remove" {
		return nil
	}
	return &AuditEvent{At: now, Actor: actor, Action: action, Resource: id}
}

// Enrollment plans admission after the backend has read the reservation and
// token, if any. The backend enforces the pending queue bound and active-name/
// realm uniqueness, and consumes the token atomically with this record.
func Enrollment(id string, p Proposal, reserved *HostRecord, token *EnrollmentToken, now time.Time) (HostRecord, error) {
	p = cloneProposal(p)
	if err := p.Validate(); err != nil {
		return HostRecord{}, err
	}
	record := HostRecord{ID: id, Revision: 1, Status: "pending", Proposal: p, CreatedAt: now, UpdatedAt: now}
	if reserved != nil {
		if !canRedeem(*reserved, token, now) {
			return HostRecord{}, ErrToken
		}
		record.ID = reserved.ID
		record.Status = "active"
		record.CreatedAt = reserved.CreatedAt
		record.Revision = reserved.Revision + 1
	}
	return record, nil
}

// PatternAdmission plans a directly admitted administrator pattern. Exact-host
// creation uses enrollment and review; it cannot use this path to skip review.
func PatternAdmission(id string, p Proposal, now time.Time) (HostRecord, error) {
	if p.Pattern == "" {
		return HostRecord{}, fmt.Errorf("pattern is required")
	}
	p = cloneProposal(p)
	if err := p.Validate(); err != nil {
		return HostRecord{}, err
	}
	return HostRecord{ID: id, Revision: 1, Status: "active", Proposal: p, CreatedAt: now, UpdatedAt: now}, nil
}

// Reservation constructs the empty record and expiring single-use credential
// which the backend persists together. IDs/secrets are generated by the backend.
func Reservation(id string, lifetime time.Duration, now time.Time) (HostRecord, EnrollmentToken, error) {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return HostRecord{}, EnrollmentToken{}, fmt.Errorf("token lifetime must be positive and no more than 24h")
	}
	return HostRecord{ID: id, Revision: 1, Status: "pending", CreatedAt: now, UpdatedAt: now}, EnrollmentToken{ID: id, ExpiresAt: now.Add(lifetime)}, nil
}

// Validation normalizes/sorts names. Copy collections before planning so failed
// operations cannot alter a caller's proposal or current snapshot.
func cloneProposal(p Proposal) Proposal {
	p.Names = slices.Clone(p.Names)
	p.Labels = maps.Clone(p.Labels)
	p.Accounts = slices.Clone(p.Accounts)
	return p
}
