package sqlitestore

import (
	"context"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"time"
)

// Change expresses existing lifecycle test scenarios through whole-record replacement.
func (m *Store) Change(ctx context.Context, actor, action, id string, revision uint64, p *inventory.Proposal) (*inventory.HostRecord, error) {
	if action == "remove" {
		return nil, m.Remove(ctx, actor, id, revision)
	}
	h, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	switch action {
	case "edit":
		if p != nil {
			h.Proposal = *p
		}
	case "approve":
		h.Status = "active"
	case "deny":
		h.Status = "denied"
	}
	return m.Replace(ctx, actor, *h, revision)
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
