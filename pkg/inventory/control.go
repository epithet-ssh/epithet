package inventory

import "github.com/epithet-ssh/epithet/pkg/inventoryapi"

// ControlProposal projects the proposal onto the control API. Slices and maps are shared,
// not cloned, so nil (unrestricted accounts) and empty (no accounts) survive.
func (p Proposal) ControlProposal() inventoryapi.Proposal {
	return inventoryapi.Proposal{
		Names:         p.Names,
		Labels:        p.Labels,
		Accounts:      p.Accounts,
		PrincipalMode: string(p.PrincipalMode),
		Domain:        p.Domain,
	}
}

// ProposalFromControl adopts a control API proposal without validating it; callers
// validate through Validate or the store operation that consumes it.
func ProposalFromControl(p inventoryapi.Proposal) Proposal {
	return Proposal{
		Names:         p.Names,
		Labels:        p.Labels,
		Accounts:      p.Accounts,
		PrincipalMode: PrincipalMode(p.PrincipalMode),
		Domain:        p.Domain,
	}
}

// ControlRecord projects the record onto the control API.
func (r HostRecord) ControlRecord() inventoryapi.HostRecord {
	return inventoryapi.HostRecord{
		SourceFile:    r.SourceFile,
		Pattern:       r.Pattern,
		ID:            r.ID,
		Revision:      r.Revision,
		Status:        r.Status,
		Proposal:      r.Proposal.ControlProposal(),
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
		Source:        r.Source,
		ShadowedNames: r.ShadowedNames,
	}
}

// ControlToken projects the token onto the control API.
func (t EnrollmentToken) ControlToken() inventoryapi.EnrollmentToken {
	return inventoryapi.EnrollmentToken{ID: t.ID, ExpiresAt: t.ExpiresAt, UsedBy: t.UsedBy, Revoked: t.Revoked}
}

// ControlEvent projects the audit event onto the control API.
func (e AuditEvent) ControlEvent() inventoryapi.HostAuditEvent {
	return inventoryapi.HostAuditEvent{At: e.At, Actor: e.Actor, Action: e.Action, Resource: e.Resource}
}
