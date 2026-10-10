package server

import (
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
)

// Projections from storage types onto the control API. Host records convert
// through pkg/facts/inventory; directory types convert here so pkg/facts/directory never
// learns the shared protocol's shape.

func controlRecord(r *inventory.HostRecord) *facts.HostRecord {
	if r == nil {
		return nil
	}
	v := r.ControlRecord()
	return &v
}

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

func controlBindings(s directory.BindingSnapshot) *facts.BindingSnapshot {
	return &facts.BindingSnapshot{Revision: s.Revision, Groups: controlSlice(s.Groups, controlGroupBinding)}
}

func controlUser(u directory.User) facts.DirectoryUser {
	return facts.DirectoryUser{UserName: u.UserName, ID: u.ID, Active: u.Active,
		Groups: u.Groups, UserType: u.UserType, Department: u.Department, Organization: u.Organization}
}

func controlGroupBinding(g directory.GroupBinding) facts.GroupBinding {
	return facts.GroupBinding{ID: g.ID, DisplayName: g.DisplayName, Alias: g.Alias, Status: g.Status}
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
	return &facts.Actor{UserName: u.UserName, ID: u.ID, Active: u.Active, Groups: u.Groups, UserType: u.UserType, Department: u.Department, Organization: u.Organization}
}
