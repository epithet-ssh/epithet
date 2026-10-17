package sqlitestore

import (
	"context"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
)

// Change expresses existing lifecycle test scenarios through whole-record replacement.
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
	case "approve":
		h.Status = inventory.StatusActive
	case "deny":
		h.Status = inventory.StatusDenied
	}
	event := inventory.NewAuditEvent(actor, action, h.ID)
	_, event.Action, err = inventory.Review(current, *h, expectedVersion, event.At)
	if err != nil {
		return nil, err
	}
	return m.UpsertHost(ctx, *h, inventory.WriteConditions{ExpectedVersion: expectedVersion}, event)
}

// Tokens inspects stored credentials for persistence tests, not for clients.
func (m *Store) Tokens(ctx context.Context, after string, limit int) ([]inventory.EnrollmentToken, error) {
	limit, err := recordPage(after, limit)
	if err != nil {
		return nil, err
	}
	rows, err := m.db.QueryContext(ctx, "SELECT host_id,expires,used,revoked FROM tokens WHERE host_id>? ORDER BY host_id LIMIT ?", after, limit)
	if err != nil {
		return nil, storageError(err)
	}
	defer rows.Close()
	tokens := []inventory.EnrollmentToken{}
	for rows.Next() {
		var t inventory.EnrollmentToken
		var expires string
		var used bool
		if err = rows.Scan(&t.ID, &expires, &used, &t.Revoked); err != nil {
			return nil, storageError(err)
		}
		if t.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires); err != nil {
			return nil, storageError(err)
		}
		if used {
			t.UsedBy = t.ID
		}
		tokens = append(tokens, t)
	}
	return tokens, storageError(rows.Err())
}
