package inventoryserver

import (
	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
)

// Projections from storage types onto the control API. Host records convert
// through pkg/inventory; directory types convert here so pkg/directory never
// learns the inventory API's shape.

func controlRecord(r *inventory.HostRecord) *inventoryapi.HostRecord {
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

func controlBindings(s directory.BindingSnapshot) *inventoryapi.BindingSnapshot {
	return &inventoryapi.BindingSnapshot{Revision: s.Revision, Groups: controlSlice(s.Groups, controlGroupBinding)}
}

func controlGroupBinding(g directory.GroupBinding) inventoryapi.GroupBinding {
	return inventoryapi.GroupBinding{ID: g.ID, DisplayName: g.DisplayName, Alias: g.Alias, Status: g.Status}
}

func controlDirectoryEvent(e directory.AuditEvent) inventoryapi.DirectoryAuditEvent {
	return inventoryapi.DirectoryAuditEvent{
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
