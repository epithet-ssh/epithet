package inventory

import "github.com/epithet-ssh/epithet/pkg/facts"

// ControlProposal projects the proposal onto the control API. Slices and maps are shared,
// not cloned, so nil (unrestricted accounts) and empty (no accounts) survive.
func (p Proposal) ControlProposal() facts.Proposal {
	return facts.Proposal{
		Names:         p.Names,
		Pattern:       p.Pattern,
		Labels:        p.Labels,
		Accounts:      p.Accounts,
		PrincipalMode: string(p.PrincipalMode),
		Realm:         p.Realm,
	}
}

// ProposalFromControl adopts a control API proposal without validating it; callers
// validate through Validate or the store operation that consumes it.
func ProposalFromControl(p facts.Proposal) Proposal {
	return Proposal{
		Names:         p.Names,
		Pattern:       p.Pattern,
		Labels:        p.Labels,
		Accounts:      p.Accounts,
		PrincipalMode: PrincipalMode(p.PrincipalMode),
		Realm:         p.Realm,
	}
}

// ControlRecord projects the record onto the control API.
func (r HostRecord) ControlRecord() facts.HostRecord {
	return facts.HostRecord{
		ID:        r.ID,
		Revision:  r.Revision,
		Status:    r.Status,
		Proposal:  r.Proposal.ControlProposal(),
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

// ControlToken projects the token onto the control API.
func (t EnrollmentToken) ControlToken() facts.EnrollmentToken {
	return facts.EnrollmentToken{ID: t.ID, ExpiresAt: t.ExpiresAt, UsedBy: t.UsedBy, Revoked: t.Revoked}
}

// ControlEvent projects the audit event onto the control API.
func (e AuditEvent) ControlEvent() facts.HostAuditEvent {
	return facts.HostAuditEvent{Sequence: uint64(e.Sequence), At: e.At, Actor: e.Actor, Action: e.Action, Resource: e.Resource}
}
