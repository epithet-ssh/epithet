package inmemory

import (
	"context"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
)

type memInv struct {
	hosts map[string]inventory.Host

	audit []inventory.AuditEvent
}

func (m *memInv) SupportsVersioning() bool { return false }

func (m *memInv) UpsertHost(ctx context.Context, host inventory.Host, conditions inventory.WriteConditions, event inventory.AuditEvent) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) LookupHost(ctx context.Context, s string) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) RemoveHost(ctx context.Context, id string, expectedVersion string, event inventory.AuditEvent) error {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) GetHost(ctx context.Context, id string) (*inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) ListHosts(ctx context.Context, after string, limit int) ([]inventory.Host, error) {
	//TODO implement me
	panic("implement me")
}

func (m *memInv) Audit(ctx context.Context, cursor string, limit int) ([]inventory.AuditEvent, string, error) {
	//TODO implement me
	panic("implement me")
}
