package sqlitestore

import (
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func TestTokenCreatesPendingHostReservation(t *testing.T) {
	m, path := managedFixture(t, "")
	id1 := inventory.NewID()
	token, err := m.CreateToken(t.Context(), id1, time.Hour, inventory.NewAuditEvent("admin", "token-create", id1))
	require.NoError(t, err)
	host, err := m.GetHost(t.Context(), token.ID)
	require.NoError(t, err)
	require.Equal(t, "pending", host.Status)
	require.True(t, inventory.EmptyHost(*host))
	require.EqualValues(t, 1, host.Revision)
	hosts, err := m.ListHosts(t.Context(), "", 0, false)
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	require.Equal(t, host.ID, hosts[0].ID)
	for _, name := range []string{token.ID, "future.example"} {
		got, err := m.LookupHost(t.Context(), name)
		require.NoError(t, err)
		require.Nil(t, got, "a reservation supplies no issuance facts")
	}
	_, err = m.Change(t.Context(), "admin", "approve", host.ID, host.Revision, nil)
	require.ErrorContains(t, err, "host attributes are required")
	require.NoError(t, m.Close())
	fresh, err := Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	pending, err := fresh.GetHost(t.Context(), host.ID)
	require.NoError(t, err)
	require.Equal(t, host.CreatedAt, pending.CreatedAt)
	require.Equal(t, "pending", pending.Status)
	id2 := token.ID
	admitted, err := fresh.Enroll(t.Context(), id2, proposal("future.example"), token.ID, inventory.NewAuditEvent("host", "enroll", id2))
	require.NoError(t, err)
	require.Equal(t, host.ID, admitted.ID)
	require.Equal(t, host.CreatedAt, admitted.CreatedAt)
	require.Equal(t, host.Revision+1, admitted.Revision)
	require.Equal(t, "active", admitted.Status)
	got, err := fresh.LookupHost(t.Context(), "future.example")
	require.NoError(t, err)
	require.NotNil(t, got)
	audit, _, err := fresh.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Len(t, audit, 2)
	require.Equal(t, "admin", audit[0].Actor)
	require.Equal(t, "token-create", audit[0].Action)
	require.Equal(t, "enroll", audit[1].Action)
}

func TestReservationCannotBeClaimedAfterWithdrawal(t *testing.T) {
	for _, action := range []string{"deny", "remove", "token-revoke", "expire"} {
		t.Run(action, func(t *testing.T) {
			m, path := managedFixture(t, "")
			id3 := inventory.NewID()
			token, err := m.CreateToken(t.Context(), id3, time.Hour, inventory.NewAuditEvent("admin", "token-create", id3))
			require.NoError(t, err)
			h, err := m.GetHost(t.Context(), token.ID)
			require.NoError(t, err)
			switch action {
			case "token-revoke":
				require.NoError(t, m.RevokeToken(t.Context(), token.ID, inventory.NewAuditEvent("admin", "token-revoke", token.ID)))
			case "expire":
				_, err = m.db.Exec("UPDATE tokens SET expires=? WHERE host_id=?", time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), token.ID)
				require.NoError(t, err)
			default:
				_, err = m.Change(t.Context(), "admin", action, h.ID, h.Revision, nil)
				require.NoError(t, err)
			}
			require.NoError(t, m.Close())
			fresh, err := Open(path)
			require.NoError(t, err)
			defer fresh.Close()
			id4 := token.ID
			_, err = fresh.Enroll(t.Context(), id4, proposal("future.example"), token.ID, inventory.NewAuditEvent("host", "enroll", id4))
			require.ErrorIs(t, err, inventory.ErrToken)
			got, err := fresh.LookupHost(t.Context(), "future.example")
			require.NoError(t, err)
			require.Nil(t, got)
		})
	}
}

func TestAdministratorCanCompleteReservationWithoutRedeemingToken(t *testing.T) {
	m, path := managedFixture(t, "")
	id5 := inventory.NewID()
	token, err := m.CreateToken(t.Context(), id5, time.Hour, inventory.NewAuditEvent("admin", "token-create", id5))
	require.NoError(t, err)
	h, err := m.GetHost(t.Context(), token.ID)
	require.NoError(t, err)
	p := proposal("managed.example")
	h, err = m.Change(t.Context(), "admin", "edit", h.ID, h.Revision, &p)
	require.NoError(t, err)
	h, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	require.Equal(t, "active", h.Status)
	id6 := token.ID
	_, err = m.Enroll(t.Context(), id6, proposal("replacement.example"), token.ID, inventory.NewAuditEvent("host", "enroll", id6))
	require.ErrorIs(t, err, inventory.ErrToken)
	require.NoError(t, m.Close())
	fresh, err := Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	got, err := fresh.LookupHost(t.Context(), "managed.example")
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestOrdinaryPendingHostDoesNotGrantPreapproval(t *testing.T) {
	m, _ := managedFixture(t, "")
	id7 := inventory.NewID()
	h, err := m.Enroll(t.Context(), id7, proposal("pending.example"), "", inventory.NewAuditEvent("host", "enroll", id7))
	require.NoError(t, err)
	id8 := h.ID
	_, err = m.Enroll(t.Context(), id8, proposal("replacement.example"), h.ID, inventory.NewAuditEvent("host", "enroll", id8))
	require.ErrorIs(t, err, inventory.ErrToken)
}
