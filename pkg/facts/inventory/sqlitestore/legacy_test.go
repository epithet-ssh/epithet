package sqlitestore

import (
	"context"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
)

// Change expresses edit/removal test scenarios through whole-record operations.
func (m *Store) Change(ctx context.Context, actor, action, id string, expectedVersion string, p *inventory.Host) (*inventory.Host, error) {
	if action == "remove" {
		return nil, m.RemoveHost(ctx, id, expectedVersion, inventory.NewAuditEvent(actor, "remove", id))
	}
	h, err := m.GetHost(ctx, id)
	if err != nil {
		return nil, err
	}
	current := *h
	switch action {
	case "edit":
		if p != nil {
			h.Names, h.Labels, h.Accounts, h.PrincipalMode, h.Realm = p.Names, p.Labels, p.Accounts, p.PrincipalMode, p.Realm
		}
	}
	event := inventory.NewAuditEvent(actor, action, h.ID)
	err = h.ValidateEdit(current, expectedVersion)
	if err != nil {
		return nil, err
	}
	return m.UpsertHost(ctx, *h, inventory.WriteConditions{ExpectedVersion: expectedVersion}, event)
}
