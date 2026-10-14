package inmemory

import (
	"context"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
)

type memInv struct {
	hosts  map[string]inventory.Host
	tokens map[string]struct{}
	audit  []inventory.AuditEvent
}

func (m *memInv) CreateHost(ctx context.Context, id string, host inventory.Host, event inventory.AuditEvent) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) RedeemToken(ctx context.Context, id string, event inventory.AuditEvent) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) LookupHost(ctx context.Context, s string) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) Enroll(ctx context.Context, id string, proposal inventory.Host, token string, event inventory.AuditEvent) (*inventory.Host, error) {
	status := inventory.StatusPending
	if token != "" {
		if _, found := m.tokens[token]; !found {
			status = inventory.StatusActive
			delete(m.tokens, token)
		}
	}
	proposal.Status = status
	m.hosts[id] = proposal
	return &proposal, nil
}

func (m *memInv) AddHost(ctx context.Context, id string, proposal inventory.Host, event inventory.AuditEvent) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) ReplaceHost(ctx context.Context, record inventory.Host, revision uint64, event inventory.AuditEvent) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) RemoveHost(ctx context.Context, id string, revision uint64, event inventory.AuditEvent) error {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) GetHost(ctx context.Context, id string) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) ListHosts(ctx context.Context, after string, limit int, pending bool) ([]inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) CreateToken(ctx context.Context, id string, lifetime time.Duration, event inventory.AuditEvent) (inventory.EnrollmentToken, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) RevokeToken(ctx context.Context, id string, event inventory.AuditEvent) error {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) Audit(ctx context.Context, cursor string, limit int) ([]inventory.AuditEvent, string, error) {
	//TODO implement me
	panic("implement me")
}
