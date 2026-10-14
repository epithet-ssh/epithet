// Package storetest provides the inventory backend contract suite. A backend
// supplies two handles to the same fresh database so concurrency tests cover
// database coordination, not just a process-local lock. The factory owns cleanup.
package storetest

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

// Backend pairs the two views of one logical inventory for contract testing.
// Embedding interfaces here does not require the same instance to implement both.
type Backend struct {
	inventory.Hosts
	inventory.Store
}

type Factory func(*testing.T) (Backend, Backend)

func Run(t *testing.T, open Factory) {
	proposal := func(name string) inventory.Proposal {
		return inventory.Proposal{Names: []string{name}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
	}
	t.Run("review and removal", func(t *testing.T) {
		store, other := open(t)
		h, err := store.Enroll(t.Context(), proposal("one.example"), "")
		require.NoError(t, err)
		got, _, err := other.LookupHost(t.Context(), "one.example")
		require.NoError(t, err)
		require.Nil(t, got)
		h.Status = "active"
		active, err := store.Replace(t.Context(), "admin", *h, h.Revision)
		require.NoError(t, err)
		_, err = other.Replace(t.Context(), "admin", *h, h.Revision)
		require.ErrorIs(t, err, inventory.ErrRevision)
		got, _, err = other.LookupHost(t.Context(), "one.example")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.NotNil(t, got.Policy.Accounts)
		require.Empty(t, got.Policy.Accounts)
		active.Proposal.Accounts = nil
		active, err = store.Replace(t.Context(), "admin", *active, active.Revision)
		require.NoError(t, err)
		got, _, err = other.LookupHost(t.Context(), "one.example")
		require.NoError(t, err)
		require.Nil(t, got.Policy.Accounts)
		require.NoError(t, store.Remove(t.Context(), "admin", active.ID, active.Revision))
		_, err = other.Get(t.Context(), active.ID)
		require.ErrorIs(t, err, inventory.ErrNotFound)
		events, err := other.Audit(t.Context(), 0, 0)
		require.NoError(t, err)
		require.Empty(t, events)
	})
	t.Run("concurrent approval", func(t *testing.T) {
		a, b := open(t)
		first, err := a.Enroll(t.Context(), proposal("same.example"), "")
		require.NoError(t, err)
		second, err := b.Enroll(t.Context(), proposal("same.example"), "")
		require.NoError(t, err)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		start := make(chan struct{})
		for i, s := range []inventory.Store{a, b} {
			h := []*inventory.HostRecord{first, second}[i]
			wg.Go(func() {
				<-start
				h.Status = "active"
				_, err := s.Replace(t.Context(), "admin", *h, h.Revision)
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
		a, b := open(t)
		token, err := a.CreateToken(t.Context(), "admin", time.Hour)
		require.NoError(t, err)
		reserved, err := b.Get(t.Context(), token.ID)
		require.NoError(t, err)
		require.True(t, inventory.EmptyProposal(reserved.Proposal))
		errs := make(chan error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, s := range []inventory.Store{a, b} {
			name := []string{"a.example", "b.example"}[i]
			wg.Go(func() { <-start; _, err := s.Enroll(t.Context(), proposal(name), token.ID); errs <- err })
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
		admitted, err := a.Get(t.Context(), token.ID)
		require.NoError(t, err)
		require.Equal(t, reserved.CreatedAt, admitted.CreatedAt)
		require.Equal(t, "active", admitted.Status)
	})
	t.Run("exact names precede patterns", func(t *testing.T) {
		a, b := open(t)
		p := proposal("ignored")
		p.Names = nil
		p.Pattern = "*.example"
		_, err := a.AddPattern(t.Context(), "admin", p)
		require.NoError(t, err)
		p.Pattern = "one.*"
		_, err = a.AddPattern(t.Context(), "admin", p)
		require.NoError(t, err)
		_, _, err = b.LookupHost(t.Context(), "one.example")
		require.ErrorIs(t, err, inventory.ErrConflict)
		h, err := a.Enroll(t.Context(), proposal("one.example"), "")
		require.NoError(t, err)
		h.Status = "active"
		_, err = a.Replace(t.Context(), "admin", *h, h.Revision)
		require.NoError(t, err)
		got, _, err := b.LookupHost(t.Context(), "one.example")
		require.NoError(t, err)
		require.Equal(t, []string{"one.example"}, got.Policy.Names)
	})
}
