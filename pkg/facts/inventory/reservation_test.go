package inventory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTokenCreatesPendingHostReservation(t *testing.T) {
	m, path := managedFixture(t, "")
	token, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	host, err := m.Get(token.ID)
	require.NoError(t, err)
	require.Equal(t, "pending", host.Status)
	require.True(t, host.Proposal.empty())
	require.EqualValues(t, 1, host.Revision)
	hosts, err := m.List()
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	require.Equal(t, host.ID, hosts[0].ID)
	for _, name := range []string{token.ID, "future.example"} {
		got, _, err := m.LookupHost(t.Context(), name)
		require.NoError(t, err)
		require.Nil(t, got, "a reservation supplies no issuance facts")
	}
	_, err = m.Change("admin", "approve", host.ID, host.Revision, nil)
	require.ErrorContains(t, err, "host attributes are required")
	require.NoError(t, m.Close())
	fresh, err := OpenManaged(path)
	require.NoError(t, err)
	defer fresh.Close()
	pending, err := fresh.Get(host.ID)
	require.NoError(t, err)
	require.Equal(t, host.CreatedAt, pending.CreatedAt)
	require.Equal(t, "pending", pending.Status)
	admitted, err := fresh.Enroll(proposal("future.example"), token.ID)
	require.NoError(t, err)
	require.Equal(t, host.ID, admitted.ID)
	require.Equal(t, host.CreatedAt, admitted.CreatedAt)
	require.Equal(t, host.Revision+1, admitted.Revision)
	require.Equal(t, "active", admitted.Status)
	got, _, err := fresh.LookupHost(t.Context(), "future.example")
	require.NoError(t, err)
	require.NotNil(t, got)
	audit, err := fresh.Audit()
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
			token, err := m.CreateToken("admin", time.Hour)
			require.NoError(t, err)
			h, err := m.Get(token.ID)
			require.NoError(t, err)
			switch action {
			case "token-revoke":
				require.NoError(t, m.RevokeToken("admin", token.ID))
			case "expire":
				_, err = m.db.Exec("UPDATE tokens SET expires=? WHERE host_id=?", time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), token.ID)
				require.NoError(t, err)
			default:
				_, err = m.Change("admin", action, h.ID, h.Revision, nil)
				require.NoError(t, err)
			}
			require.NoError(t, m.Close())
			fresh, err := OpenManaged(path)
			require.NoError(t, err)
			defer fresh.Close()
			_, err = fresh.Enroll(proposal("future.example"), token.ID)
			require.ErrorIs(t, err, ErrToken)
			got, _, err := fresh.LookupHost(t.Context(), "future.example")
			require.NoError(t, err)
			require.Nil(t, got)
		})
	}
}

func TestAdministratorCanCompleteReservationWithoutRedeemingToken(t *testing.T) {
	m, path := managedFixture(t, "")
	token, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	h, err := m.Get(token.ID)
	require.NoError(t, err)
	p := proposal("managed.example")
	h, err = m.Change("admin", "edit", h.ID, h.Revision, &p)
	require.NoError(t, err)
	h, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	require.Equal(t, "active", h.Status)
	_, err = m.Enroll(proposal("replacement.example"), token.ID)
	require.ErrorIs(t, err, ErrToken)
	require.NoError(t, m.Close())
	fresh, err := OpenManaged(path)
	require.NoError(t, err)
	defer fresh.Close()
	got, _, err := fresh.LookupHost(t.Context(), "managed.example")
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestOrdinaryPendingHostDoesNotGrantPreapproval(t *testing.T) {
	m, _ := managedFixture(t, "")
	h, err := m.Enroll(proposal("pending.example"), "")
	require.NoError(t, err)
	_, err = m.Enroll(proposal("replacement.example"), h.ID)
	require.ErrorIs(t, err, ErrToken)
}
