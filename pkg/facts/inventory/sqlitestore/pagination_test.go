package sqlitestore

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func TestInventoryRecordPagesAndPendingFilter(t *testing.T) {
	m, _ := managedFixture(t, "")
	var id int
	m.newID = func() (string, error) { id++; return fmt.Sprintf("%064x", id), nil }
	for n := 0; n < 125; n++ {
		_, err := m.CreateToken(t.Context(), "admin", time.Hour)
		require.NoError(t, err)
	}
	first, err := m.List(t.Context(), "", 0, false)
	require.NoError(t, err)
	require.Len(t, first, inventory.DefaultPageLimit)
	last, err := m.List(t.Context(), first[len(first)-1].ID, 0, false)
	require.NoError(t, err)
	require.Len(t, last, 25)
	require.Greater(t, last[0].ID, first[len(first)-1].ID)
	empty, err := m.List(t.Context(), last[len(last)-1].ID, 0, false)
	require.NoError(t, err)
	require.Empty(t, empty)

	// Filtering must happen before the limit, including when an earlier ID has
	// moved out of pending. A removed cursor must still allow continuation.
	p := proposal("host")
	h, err := m.Change(t.Context(), "admin", "edit", first[0].ID, first[0].Revision, &p)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	pending, err := m.List(t.Context(), "", 3, true)
	require.NoError(t, err)
	require.Len(t, pending, 3)
	require.Equal(t, first[1].ID, pending[0].ID)
	_, err = m.Change(t.Context(), "admin", "remove", first[4].ID, first[4].Revision, nil)
	require.NoError(t, err)
	page, err := m.List(t.Context(), first[4].ID, 1, false)
	require.NoError(t, err)
	require.Equal(t, first[5].ID, page[0].ID)

	var after string
	var tokens []inventory.EnrollmentToken
	for {
		page, err := m.Tokens(t.Context(), after, 17)
		require.NoError(t, err)
		require.LessOrEqual(t, len(page), 17)
		if len(page) == 0 {
			break
		}
		for _, token := range page {
			require.Greater(t, token.ID, after)
			after = token.ID
			tokens = append(tokens, token)
		}
	}
	require.Len(t, tokens, 124)
	for _, limit := range []int{-1, inventory.MaxPageLimit + 1} {
		_, err := m.List(t.Context(), "", limit, false)
		require.ErrorContains(t, err, "limit")
		_, err = m.Tokens(t.Context(), "", limit)
		require.ErrorContains(t, err, "limit")
		_, err = m.Audit(t.Context(), 0, limit)
		require.ErrorContains(t, err, "limit")
	}
	for _, after := range []string{"short", strings.Repeat("A", 64)} {
		_, err := m.List(t.Context(), after, 1, false)
		require.ErrorContains(t, err, "full record ID")
		_, err = m.Tokens(t.Context(), after, 1)
		require.ErrorContains(t, err, "full record ID")
	}
}

func TestAuditSequencesSurviveDeletionRestartAndClockOrder(t *testing.T) {
	m, path := managedFixture(t, "")
	_, err := m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	last, err := m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	// Clock order cannot reorder or skip events in a sequence-based page.
	_, err = m.db.Exec("UPDATE audit SET time=? WHERE sequence=1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	require.NoError(t, err)
	first, err := m.Audit(t.Context(), 0, 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, first[0].Sequence)
	second, err := m.Audit(t.Context(), first[0].Sequence, 1)
	require.NoError(t, err)
	require.EqualValues(t, 2, second[0].Sequence)
	_, err = m.Change(t.Context(), "admin", "remove", last.ID, 1, nil)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	m, err = Open(path)
	require.NoError(t, err)
	defer m.Close()
	_, err = m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	next, err := m.Audit(t.Context(), second[0].Sequence, 1)
	require.NoError(t, err)
	require.Len(t, next, 1)
	require.Greater(t, next[0].Sequence, second[0].Sequence)
	empty, err := m.Audit(t.Context(), next[0].Sequence, 1)
	require.NoError(t, err)
	require.Empty(t, empty)
}
