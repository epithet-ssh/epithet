// Package storetest provides the inventory backend contract suite. A backend
// supplies one fresh inventory. The factory owns cleanup.
package storetest

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/stretchr/testify/require"
)

// Backend pairs the two views of one logical inventory for contract testing.
// Embedding interfaces here does not require the same instance to implement both.
type Backend struct {
	inventory.Hosts
	inventory.Store
}

type Factory func(*testing.T) Backend

func Run(t *testing.T, open Factory) {
	proposal := func(name string) inventory.Host {
		return inventory.Host{Names: []string{name}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
	}
	t.Run("caller supplied IDs and audit events", func(t *testing.T) {
		store := open(t)
		ctx := t.Context()
		var expected []inventory.AuditEvent
		event := func(action, id string) inventory.AuditEvent {
			// Deliberately distinct from storage's former vocabulary and clock.
			e := inventory.AuditEvent{At: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC).Add(-time.Duration(len(expected)) * time.Hour), Actor: "supplied-actor", Action: "supplied-" + action, Resource: id}
			expected = append(expected, e)
			return e
		}
		id := inventory.NewID()
		h, err := store.Enroll(ctx, id, proposal("audit.example"), "", event("enroll", id))
		require.NoError(t, err)
		require.Equal(t, id, h.ID)
		require.Equal(t, expected[0].At, h.CreatedAt)
		h.Status = "active"
		h, err = store.ReplaceHost(ctx, *h, h.Revision, event("approve", id))
		require.NoError(t, err)
		patternID := inventory.NewID()
		p := inventory.Host{Names: []string{"*.audit.example"}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
		pattern, err := store.AddHost(ctx, patternID, p, event("pattern", patternID))
		require.NoError(t, err)
		require.Equal(t, patternID, pattern.ID)
		tokenID := inventory.NewID()
		token, err := store.CreateToken(ctx, tokenID, time.Hour, event("token", tokenID))
		require.NoError(t, err)
		require.Equal(t, tokenID, token.ID)
		require.NoError(t, store.RevokeToken(ctx, tokenID, event("revoke", tokenID)))
		require.NoError(t, store.RemoveHost(ctx, id, h.Revision, event("remove", id)))
		var actual []inventory.AuditEvent
		var cursor string
		for {
			page, next, err := store.Audit(ctx, cursor, 2)
			require.NoError(t, err)
			require.LessOrEqual(t, len(page), 2)
			actual = append(actual, page...)
			cursor = next
			if cursor == "" {
				break
			}
		}
		require.ElementsMatch(t, expected, actual, "Storage must preserve all supplied fields and retain history after removal")
	})
	t.Run("list and audit pages", func(t *testing.T) {
		store := open(t)
		ctx := t.Context()
		const count = inventory.DefaultPageLimit + 2
		ids := make([]string, count)
		for i := count - 1; i >= 0; i-- {
			id := fmt.Sprintf("%064x", i+1)
			ids[i] = id
			_, err := store.CreateToken(ctx, id, time.Hour, inventory.NewAuditEvent("admin", "token-create", id))
			require.NoError(t, err)
		}
		first, err := store.ListHosts(ctx, "", 0, false)
		require.NoError(t, err)
		require.Len(t, first, inventory.DefaultPageLimit)
		var after string
		for start := 0; start < count; start += 17 {
			page, err := store.ListHosts(ctx, after, 17, false)
			require.NoError(t, err)
			require.Len(t, page, min(17, count-start))
			for i, h := range page {
				require.Equal(t, ids[start+i], h.ID)
			}
			after = page[len(page)-1].ID
		}
		empty, err := store.ListHosts(ctx, after, 17, false)
		require.NoError(t, err)
		require.Empty(t, empty)
		// Filter before applying the limit, even when the cursor has been deleted.
		h, err := store.GetHost(ctx, ids[0])
		require.NoError(t, err)
		h.Status = "denied"
		_, err = store.ReplaceHost(ctx, *h, h.Revision, inventory.NewAuditEvent("admin", "deny", h.ID))
		require.NoError(t, err)
		require.NoError(t, store.RemoveHost(ctx, ids[1], 1, inventory.NewAuditEvent("admin", "remove", ids[1])))
		for _, cursor := range []string{"", ids[1]} {
			page, err := store.ListHosts(ctx, cursor, 2, true)
			require.NoError(t, err)
			require.Len(t, page, 2)
			require.Equal(t, ids[2], page[0].ID)
			require.Equal(t, ids[3], page[1].ID)
		}
		firstEvents, _, err := store.Audit(ctx, "", 0)
		require.NoError(t, err)
		require.LessOrEqual(t, len(firstEvents), inventory.DefaultPageLimit)
		var cursor string
		var events []inventory.AuditEvent
		for {
			page, next, err := store.Audit(ctx, cursor, 17)
			require.NoError(t, err)
			require.LessOrEqual(t, len(page), 17)
			events = append(events, page...)
			cursor = next
			if cursor == "" {
				break
			}
		}
		var createdIDs []string
		for _, e := range events {
			if e.Action == "token-create" {
				createdIDs = append(createdIDs, e.Resource)
			}
		}
		require.Len(t, events, count+2)
		require.ElementsMatch(t, ids, createdIDs)
	})
	t.Run("review and removal", func(t *testing.T) {
		store := open(t)
		id1 := inventory.NewID()
		h, err := store.Enroll(t.Context(), id1, proposal("one.example"), "", inventory.NewAuditEvent("host", "enroll", id1))
		require.NoError(t, err)
		got, err := store.LookupHost(t.Context(), "one.example")
		require.NoError(t, err)
		require.Nil(t, got)
		h.Status = "active"
		active, err := store.ReplaceHost(t.Context(), *h, h.Revision, inventory.NewAuditEvent("admin", "approve", h.ID))
		require.NoError(t, err)
		_, err = store.ReplaceHost(t.Context(), *h, h.Revision, inventory.NewAuditEvent("admin", "approve", h.ID))
		require.ErrorIs(t, err, inventory.ErrRevision)
		got, err = store.LookupHost(t.Context(), "one.example")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.NotNil(t, got.Accounts)
		require.Empty(t, got.Accounts)
		active.Accounts = nil
		active, err = store.ReplaceHost(t.Context(), *active, active.Revision, inventory.NewAuditEvent("admin", "edit", active.ID))
		require.NoError(t, err)
		got, err = store.LookupHost(t.Context(), "one.example")
		require.NoError(t, err)
		require.Nil(t, got.Accounts)
		require.NoError(t, store.RemoveHost(t.Context(), active.ID, active.Revision, inventory.NewAuditEvent("admin", "remove", active.ID)))
		_, err = store.GetHost(t.Context(), active.ID)
		require.ErrorIs(t, err, inventory.ErrNotFound)
	})
	t.Run("shared realms have independent host facts", func(t *testing.T) {
		for _, realm := range []string{"fleet", "epithet-host-id-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
			t.Run(realm, func(t *testing.T) {
				store := open(t)
				ctx := t.Context()
				firstHost := proposal("first.example")
				firstHost.PrincipalMode, firstHost.Realm = inventory.EpithetPrincipalV1, principal.Realm(realm)
				firstHost.Labels = map[string]string{"role": "first"}
				firstID := inventory.NewID()
				first, err := store.Enroll(ctx, firstID, firstHost, "", inventory.NewAuditEvent("host", "enroll", firstID))
				require.NoError(t, err)
				first.Status = "active"
				first, err = store.ReplaceHost(ctx, *first, first.Revision, inventory.NewAuditEvent("admin", "approve", firstID))
				require.NoError(t, err)

				secondHost := proposal("second.example")
				secondHost.PrincipalMode, secondHost.Realm = inventory.EpithetPrincipalV1, principal.Realm(realm)
				secondHost.Labels = map[string]string{"role": "second"}
				secondHost.Accounts = nil
				secondID := inventory.NewID()
				token, err := store.CreateToken(ctx, secondID, time.Hour, inventory.NewAuditEvent("admin", "token-create", secondID))
				require.NoError(t, err)
				_, err = store.Enroll(ctx, secondID, secondHost, token.ID, inventory.NewAuditEvent("host", "enroll", secondID))
				require.NoError(t, err)

				first.Labels = map[string]string{"role": "edited"}
				first.Accounts = []string{"deploy"}
				_, err = store.ReplaceHost(ctx, *first, first.Revision, inventory.NewAuditEvent("admin", "edit", firstID))
				require.NoError(t, err)

				patternID := inventory.NewID()
				pattern := inventory.Host{Names: []string{"runner-*.example"}, PrincipalMode: inventory.EpithetPrincipalV1, Realm: principal.Realm(realm),
					Labels: map[string]string{"role": "runner"}, Accounts: []string{"root"}}
				_, err = store.AddHost(ctx, patternID, pattern, inventory.NewAuditEvent("admin", "add", patternID))
				require.NoError(t, err)

				for _, expected := range []struct {
					name, role string
					accounts   []string
				}{
					{"first.example", "edited", []string{"deploy"}},
					{"second.example", "second", nil},
					{"runner-one.example", "runner", []string{"root"}},
				} {
					h, err := store.LookupHost(ctx, expected.name)
					require.NoError(t, err)
					require.NotNil(t, h)
					require.Equal(t, realm, string(h.Realm))
					require.Equal(t, expected.role, h.Labels["role"])
					require.Equal(t, expected.accounts, h.Accounts)
				}
			})
		}
	})
	t.Run("concurrent approval", func(t *testing.T) {
		store := open(t)
		id2 := inventory.NewID()
		first, err := store.Enroll(t.Context(), id2, proposal("same.example"), "", inventory.NewAuditEvent("host", "enroll", id2))
		require.NoError(t, err)
		id3 := inventory.NewID()
		second, err := store.Enroll(t.Context(), id3, proposal("same.example"), "", inventory.NewAuditEvent("host", "enroll", id3))
		require.NoError(t, err)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		start := make(chan struct{})
		for _, h := range []*inventory.Host{first, second} {
			wg.Go(func() {
				<-start
				h.Status = "active"
				_, err := store.ReplaceHost(t.Context(), *h, h.Revision, inventory.NewAuditEvent("admin", "approve", h.ID))
				errs <- err
			})
		}
		close(start)
		wg.Wait()
		close(errs)
		success, conflict := 0, 0
		for err := range errs {
			if err == nil {
				success++
			} else if errors.Is(err, inventory.ErrConflict) {
				conflict++
			} else {
				t.Fatal(err)
			}
		}
		require.Equal(t, 1, success)
		require.Equal(t, 1, conflict)
	})
	t.Run("single-use reservation", func(t *testing.T) {
		store := open(t)
		id4 := inventory.NewID()
		token, err := store.CreateToken(t.Context(), id4, time.Hour, inventory.NewAuditEvent("admin", "token-create", id4))
		require.NoError(t, err)
		reserved, err := store.GetHost(t.Context(), token.ID)
		require.NoError(t, err)
		require.True(t, inventory.EmptyHost(*reserved))
		errs := make(chan error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, name := range []string{"a.example", "b.example"} {
			wg.Go(func() {
				<-start
				id5 := token.ID
				_, err := store.Enroll(t.Context(), id5, proposal(name), token.ID, inventory.NewAuditEvent("host", "enroll", id5))
				errs <- err
			})
		}
		close(start)
		wg.Wait()
		close(errs)
		success, rejected := 0, 0
		for err := range errs {
			if err == nil {
				success++
			} else if errors.Is(err, inventory.ErrToken) {
				rejected++
			} else {
				t.Fatal(err)
			}
		}
		require.Equal(t, 1, success)
		require.Equal(t, 1, rejected)
		admitted, err := store.GetHost(t.Context(), token.ID)
		require.NoError(t, err)
		require.Equal(t, reserved.CreatedAt, admitted.CreatedAt)
		require.Equal(t, "active", admitted.Status)
	})
	t.Run("exact and wildcard names share a host lifecycle", func(t *testing.T) {
		store := open(t)
		ctx := t.Context()
		id := inventory.NewID()
		host, err := store.AddHost(ctx, id, inventory.Host{
			Names:  []string{"build.example", "ci-*.example", "ci-?.example"},
			Labels: map[string]string{"team": "build"}, Accounts: []string{"deploy"},
			PrincipalMode: inventory.AccountNamePrincipals,
		}, inventory.NewAuditEvent("admin", "add", id))
		require.NoError(t, err)
		stored, err := store.GetHost(ctx, id)
		require.NoError(t, err)
		require.ElementsMatch(t, host.Names, stored.Names)
		page, err := store.ListHosts(ctx, "", 10, false)
		require.NoError(t, err)
		require.Len(t, page, 1)
		require.ElementsMatch(t, host.Names, page[0].Names)
		for _, name := range []string{"build.example", "ci-one.example", "ci-1.example"} {
			resolved, err := store.LookupHost(ctx, name)
			require.NoError(t, err, "overlapping names on one host supply the same facts")
			require.NotNil(t, resolved)
			require.Contains(t, resolved.Names, name)
			require.Equal(t, host.Labels, resolved.Labels)
			require.Equal(t, host.Accounts, resolved.Accounts)
		}
		// Replacing names updates both lookup paths and removes obsolete entries.
		host.Names = []string{"build-*.example", "ci-one.example"}
		host, err = store.ReplaceHost(ctx, *host, host.Revision, inventory.NewAuditEvent("admin", "edit", id))
		require.NoError(t, err)
		for _, name := range []string{"build.example", "ci-1.example"} {
			resolved, err := store.LookupHost(ctx, name)
			require.NoError(t, err)
			require.Nil(t, resolved)
		}
		for _, name := range []string{"build-one.example", "ci-one.example"} {
			resolved, err := store.LookupHost(ctx, name)
			require.NoError(t, err)
			require.NotNil(t, resolved)
		}
		require.NoError(t, store.RemoveHost(ctx, id, host.Revision, inventory.NewAuditEvent("admin", "remove", id)))
		for _, name := range []string{"build-one.example", "ci-one.example"} {
			resolved, err := store.LookupHost(ctx, name)
			require.NoError(t, err)
			require.Nil(t, resolved)
		}
	})
	t.Run("exact names precede patterns", func(t *testing.T) {
		store := open(t)
		p := inventory.Host{Names: []string{"*.example"}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
		id6 := inventory.NewID()
		_, err := store.AddHost(t.Context(), id6, p, inventory.NewAuditEvent("admin", "add", id6))
		require.NoError(t, err)
		p.Names = []string{"one.*"}
		id7 := inventory.NewID()
		_, err = store.AddHost(t.Context(), id7, p, inventory.NewAuditEvent("admin", "add", id7))
		require.NoError(t, err)
		_, err = store.LookupHost(t.Context(), "one.example")
		require.ErrorIs(t, err, inventory.ErrConflict)
		id8 := inventory.NewID()
		h, err := store.Enroll(t.Context(), id8, proposal("one.example"), "", inventory.NewAuditEvent("host", "enroll", id8))
		require.NoError(t, err)
		h.Status = "active"
		_, err = store.ReplaceHost(t.Context(), *h, h.Revision, inventory.NewAuditEvent("admin", "approve", h.ID))
		require.NoError(t, err)
		got, err := store.LookupHost(t.Context(), "one.example")
		require.NoError(t, err)
		require.Equal(t, []string{"one.example"}, got.Names)
	})
}
