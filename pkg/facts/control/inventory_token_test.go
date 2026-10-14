package control_test

import (
	"context"
	"fmt"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/control"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/test/controltest"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

type rejectingIdentity struct{ calls int }

func (v *rejectingIdentity) Validate(context.Context, string) (*oidc.Claims, error) {
	v.calls++
	return nil, fmt.Errorf("no identity")
}
func TestInventoryAutomationCredentialScope(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	validator := &rejectingIdentity{}
	f := controltest.New(t, nil, nil, store, control.Config{InventoryToken: "inventory-secret", SCIMToken: "directory-secret", Validator: validator})
	client, err := facts.NewAdminClient(f.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	created, _, err := client.Control(t.Context(), "inventory-secret", facts.ControlRequest{Action: "token-create"})
	require.NoError(t, err)
	require.NotEmpty(t, created.Token.ID)
	require.Zero(t, validator.calls)
	events, err := store.Audit(t.Context(), 0, 0)
	require.NoError(t, err)
	require.Equal(t, "inventory-token", events[0].Actor)
	_, status, err := client.Control(t.Context(), "directory-secret", facts.ControlRequest{Action: "list"})
	require.Error(t, err)
	require.Equal(t, 401, status)
	_, status, err = client.Control(t.Context(), created.Token.ID, facts.ControlRequest{Action: "list"})
	require.Error(t, err)
	require.Equal(t, 401, status)
	_, status, err = client.Control(t.Context(), "inventory-secret", facts.ControlRequest{Action: "directory-users"})
	require.Error(t, err)
	require.Equal(t, 401, status)
	_, status, err = client.Control(t.Context(), "inventory-secret", facts.ControlRequest{Action: "token-list"})
	require.Error(t, err)
	require.Equal(t, 400, status)
}
