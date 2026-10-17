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
	for n := 0; n < 125; n++ {
		id1 := fmt.Sprintf("%064x", n+1)
		_, err := m.CreateHost(t.Context(), id1, inventory.Host{Status: inventory.StatusPending, Names: []string{"page.example"}, PrincipalMode: inventory.AccountNamePrincipals}, inventory.NewAuditEvent("admin", "create", id1))
		require.NoError(t, err)
	}
	first, err := m.ListHosts(t.Context(), "", 0, false)
	require.NoError(t, err)
	require.Len(t, first, inventory.DefaultPageLimit)
	last, err := m.ListHosts(t.Context(), first[len(first)-1].ID, 0, false)
	require.NoError(t, err)
	require.Len(t, last, 25)
	require.Greater(t, last[0].ID, first[len(first)-1].ID)
	empty, err := m.ListHosts(t.Context(), last[len(last)-1].ID, 0, false)
	require.NoError(t, err)
	require.Empty(t, empty)

	// Filtering must happen before the limit, including when an earlier ID has
	// moved out of pending. A removed cursor must still allow continuation.
	p := proposal("host")
	h, err := m.Change(t.Context(), "admin", "edit", first[0].ID, first[0].Version, &p)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
	require.NoError(t, err)
	pending, err := m.ListHosts(t.Context(), "", 3, true)
	require.NoError(t, err)
	require.Len(t, pending, 3)
	require.Equal(t, first[1].ID, pending[0].ID)
	_, err = m.Change(t.Context(), "admin", "remove", first[4].ID, first[4].Version, nil)
	require.NoError(t, err)
	page, err := m.ListHosts(t.Context(), first[4].ID, 1, false)
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
	require.Empty(t, tokens)
	for _, limit := range []int{-1, inventory.MaxPageLimit + 1} {
		_, err := m.ListHosts(t.Context(), "", limit, false)
		require.ErrorContains(t, err, "limit")
		_, err = m.Tokens(t.Context(), "", limit)
		require.ErrorContains(t, err, "limit")
		_, _, err = m.Audit(t.Context(), "", limit)
		require.ErrorContains(t, err, "limit")
	}
	for _, after := range []string{"short", strings.Repeat("A", 64)} {
		_, err := m.ListHosts(t.Context(), after, 1, false)
		require.ErrorContains(t, err, "full record ID")
		_, err = m.Tokens(t.Context(), after, 1)
		require.ErrorContains(t, err, "full record ID")
	}
}

func TestAuditCursorSurvivesDeletionRestartAndTimestampTies(t *testing.T) {
	m, path := managedFixture(t, "")
	stamp := time.Now().UTC()
	firstID, secondID := inventory.NewID(), inventory.NewID()
	firstEvent := inventory.AuditEvent{At: stamp, Actor: "admin", Action: "token-create", Resource: firstID}
	secondEvent := inventory.AuditEvent{At: stamp, Actor: "admin", Action: "token-create", Resource: secondID}
	_, err := m.CreateHost(t.Context(), firstID, inventory.Host{Status: inventory.StatusPending, Names: []string{"page.example"}, PrincipalMode: inventory.AccountNamePrincipals}, firstEvent)
	require.NoError(t, err)
	_, err = m.CreateHost(t.Context(), secondID, inventory.Host{Status: inventory.StatusPending, Names: []string{"page.example"}, PrincipalMode: inventory.AccountNamePrincipals}, secondEvent)
	require.NoError(t, err)
	first, cursor, err := m.Audit(t.Context(), "", 1)
	require.NoError(t, err)
	require.Equal(t, []inventory.AuditEvent{firstEvent}, first)
	require.NotEmpty(t, cursor)
	removed := inventory.AuditEvent{At: stamp.Add(-time.Hour), Actor: "admin", Action: "remove", Resource: secondID}
	host, err := m.GetHost(t.Context(), secondID)
	require.NoError(t, err)
	require.NoError(t, m.RemoveHost(t.Context(), secondID, host.Version, removed))
	require.NoError(t, m.Close())
	m, err = Open(path)
	require.NoError(t, err)
	defer m.Close()
	second, next, err := m.Audit(t.Context(), cursor, 1)
	require.NoError(t, err)
	require.Equal(t, []inventory.AuditEvent{secondEvent}, second)
	require.NotEmpty(t, next)
	last, next, err := m.Audit(t.Context(), next, 1)
	require.NoError(t, err)
	require.Equal(t, []inventory.AuditEvent{removed}, last)
	require.Empty(t, next)
}
