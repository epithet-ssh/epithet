package sqlitestore

import (
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func TestEnrollmentRetriesAfterRestart(t *testing.T) {
	for _, preapproved := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "preapproved"}[preapproved], func(t *testing.T) {
			m, path := managedFixture(t, "")
			id, token := inventory.NewID(), ""
			if preapproved {
				token = id
				_, err := m.CreateToken(t.Context(), id, time.Hour, inventory.NewAuditEvent("admin", "token-create", id))
				require.NoError(t, err)
				_, err = m.GetHost(t.Context(), id)
				require.ErrorIs(t, err, inventory.ErrNotFound, "creating a token must not create a host")
				hosts, err := m.ListHosts(t.Context(), "", 0, false)
				require.NoError(t, err)
				require.Empty(t, hosts)
			}
			h, err := inventory.Enroll(t.Context(), m, id, proposal("retry.example"), token, inventory.NewAuditEvent("host", "enroll", id))
			require.NoError(t, err)
			require.Equal(t, id, h.ID)
			if preapproved {
				require.Equal(t, inventory.StatusActive, h.Status)
			} else {
				require.Equal(t, inventory.StatusPending, h.Status)
			}
			events, _, err := m.Audit(t.Context(), "", 0)
			require.NoError(t, err)
			require.NoError(t, m.Close())
			fresh, err := Open(path)
			require.NoError(t, err)
			defer fresh.Close()
			retry, err := inventory.Enroll(t.Context(), fresh, id, proposal("retry.example"), token, inventory.NewAuditEvent("host", "enroll", id))
			require.NoError(t, err)
			require.Equal(t, h, retry, "retry must preserve status, version, and timestamps")
			_, err = inventory.Enroll(t.Context(), fresh, id, proposal("changed.example"), token, inventory.NewAuditEvent("host", "enroll", id))
			if preapproved {
				require.ErrorIs(t, err, inventory.ErrToken)
			} else {
				require.ErrorIs(t, err, inventory.ErrConflict)
			}
			after, _, err := fresh.Audit(t.Context(), "", 0)
			require.NoError(t, err)
			require.Equal(t, events, after, "retry must not append an audit event")
			if !preapproved {
				approved, err := fresh.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
				require.NoError(t, err)
				retry, err = inventory.Enroll(t.Context(), fresh, id, proposal("retry.example"), "", inventory.NewAuditEvent("host", "enroll", id))
				require.NoError(t, err)
				require.Equal(t, approved, retry, "retry must not undo administrator review")
			} else {
				require.NoError(t, fresh.RemoveHost(t.Context(), id, h.Version, inventory.NewAuditEvent("admin", "remove", id)))
				_, err = inventory.Enroll(t.Context(), fresh, id, proposal("retry.example"), token, inventory.NewAuditEvent("host", "enroll", id))
				require.ErrorIs(t, err, inventory.ErrToken, "deletion must not make a consumed token reusable")
			}
		})
	}
}

func TestOrdinaryPendingHostDoesNotGrantPreapproval(t *testing.T) {
	m, _ := managedFixture(t, "")
	id := inventory.NewID()
	_, err := inventory.Enroll(t.Context(), m, id, proposal("pending.example"), "", inventory.NewAuditEvent("host", "enroll", id))
	require.NoError(t, err)
	_, err = inventory.Enroll(t.Context(), m, id, proposal("pending.example"), id, inventory.NewAuditEvent("host", "enroll", id))
	require.ErrorIs(t, err, inventory.ErrToken)
}
