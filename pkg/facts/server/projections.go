package server

import (
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
)

// Directory projections stay here so storage never learns the control protocol.

// controlSlice maps a slice element-wise, preserving nil versus empty.
func controlSlice[S, T any](in []S, f func(S) T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	for i, s := range in {
		out[i] = f(s)
	}
	return out
}

func controlGroups(s directory.GroupSnapshot) *facts.GroupSnapshot {
	return &facts.GroupSnapshot{Revision: s.Revision, Groups: controlSlice(s.Groups, controlGroupSummary)}
}

func controlUser(u directory.User) facts.DirectoryUser {
	return facts.DirectoryUser{UserName: u.UserName, ID: u.ID, Active: u.Active,
		Groups: object.GroupNames(u.Groups), UserType: u.UserType, Department: u.Department, Organization: u.Organization}
}

func controlGroupSummary(g directory.GroupSummary) facts.GroupSummary {
	return facts.GroupSummary{ID: g.ID, DisplayName: g.DisplayName, ExternalID: g.ExternalID}
}

func controlDirectoryEvent(e directory.AuditEvent) facts.DirectoryAuditEvent {
	return facts.DirectoryAuditEvent{
		Sequence:   uint64(e.Sequence),
		Revision:   e.Revision,
		Time:       e.Time,
		Actor:      e.Actor,
		Action:     e.Action,
		ID:         e.ID,
		Alias:      e.Alias,
		PreviousID: e.PreviousID,
	}
}

func controlActor(u *directory.User) *facts.Actor {
	if u == nil {
		return nil
	}
	return &facts.Actor{UserName: u.UserName, ID: u.ID, Active: u.Active, Groups: object.GroupNames(u.Groups), UserType: u.UserType, Department: u.Department, Organization: u.Organization}
}
