package sqlitestore

import (
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func TestOptionalVersionPreconditions(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	require.True(t, store.SupportsVersioning())
	id := inventory.NewID()
	h, err := store.CreateHost(t.Context(), id, inventory.Host{Version: "caller-cannot-choose", Names: []string{"host.example"}, Status: inventory.StatusPending, PrincipalMode: inventory.AccountNamePrincipals}, inventory.NewAuditEvent("admin", "create", id))
	require.NoError(t, err)
	require.NotEmpty(t, h.Version)
	require.NotEqual(t, "caller-cannot-choose", h.Version)
	firstVersion := h.Version
	h.Labels = map[string]string{"role": "updated"}
	h.Version = "ignored-input-version"
	updated, err := store.ReplaceHost(t.Context(), *h, firstVersion, inventory.NewAuditEvent("admin", "edit", id))
	require.NoError(t, err)
	require.NotEmpty(t, updated.Version)
	require.NotEqual(t, firstVersion, updated.Version)
	require.NotEqual(t, "ignored-input-version", updated.Version)
	_, err = store.ReplaceHost(t.Context(), *updated, firstVersion, inventory.NewAuditEvent("admin", "edit", id))
	require.ErrorIs(t, err, inventory.ErrVersion)
	require.ErrorIs(t, store.RemoveHost(t.Context(), id, firstVersion, inventory.NewAuditEvent("admin", "remove", id)), inventory.ErrVersion)
	unchecked, err := store.ReplaceHost(t.Context(), *updated, "", inventory.NewAuditEvent("admin", "edit", id))
	require.NoError(t, err)
	require.NotEqual(t, updated.Version, unchecked.Version)
	require.NoError(t, store.RemoveHost(t.Context(), id, "", inventory.NewAuditEvent("admin", "remove", id)))
}
