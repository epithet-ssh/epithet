package sqlitestore_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/stretchr/testify/require"
)

// These guarantees belong to SQLite, not the shared directory Store contract.
func TestSQLiteConsistency(t *testing.T) {
	t.Run("state constraints and failed writes leave state unchanged", func(t *testing.T) {
		store := openSQLite(t)
		ctx := t.Context()
		u, err := store.CreateUser(ctx, directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, ExternalID: "subject", UserName: "Alice"}, directory.NewAuditEvent(ctx, "create", "subject"))
		require.NoError(t, err, "CreateUser must accept a valid inactive user")
		g, err := store.CreateGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-ops"}, DisplayName: "ops", MemberIDs: []string{u.ID}}, directory.NewAuditEvent(ctx, "create", "group-ops"))
		require.NoError(t, err, "CreateGroup must allow membership of an inactive user")
		before, err := store.LookupUser(ctx, "subject")
		require.NoError(t, err, "LookupUser must succeed before testing failed writes")
		history, _, err := store.Audit(ctx, "", 0)
		require.NoError(t, err, "Audit must succeed before testing failed writes")
		groups, total, err := store.ListGroups(ctx, 1, 10)
		require.NoError(t, err, "ListGroups must succeed before testing failed writes")
		for _, input := range []directory.ManagedUser{
			{Metadata: directory.Metadata{ID: "other"}, UserName: "ALICE", Active: true},
			{Metadata: directory.Metadata{ID: "subject"}, UserName: "other"},
		} {
			_, err := store.CreateUser(ctx, input, directory.NewAuditEvent(ctx, "create", input.ID))
			require.ErrorIs(t, err, directory.ErrConflict, "CreateUser must return ErrConflict when supplied ID=%q or UserName=%q is already owned, including by an inactive user", input.ID, input.UserName)
		}
		for _, input := range []directory.ManagedGroup{
			{Metadata: directory.Metadata{ID: "group-invalid"}, DisplayName: "bad", MemberIDs: []string{u.ID, "missing"}},
			{Metadata: directory.Metadata{ID: "group-invalid"}, DisplayName: "bad", MemberIDs: []string{g.ID}},
		} {
			_, err := store.CreateGroup(ctx, input, directory.NewAuditEvent(ctx, "create", input.ID))
			require.ErrorIs(t, err, directory.ErrInvalid, "CreateGroup must return ErrInvalid for a member that is not an existing user resource ID; input=%+v", input)
			input.ID = g.ID
			_, err = store.ReplaceGroup(ctx, input, "", directory.NewAuditEvent(ctx, "replace", input.ID))
			require.ErrorIs(t, err, directory.ErrInvalid, "ReplaceGroup must return ErrInvalid for a member that is not an existing user resource ID; input=%+v", input)
		}
		after, err := store.LookupUser(ctx, "subject")
		require.NoError(t, err, "LookupUser must remain readable after rejected writes")
		require.Equal(t, before, after, "Rejected writes must leave the existing user's profile and memberships unchanged")

		nextHistory, _, err := store.Audit(ctx, "", 0)
		require.NoError(t, err, "Audit must remain readable after rejected writes")
		require.Equal(t, history, nextHistory, "Rejected writes must not append or alter audit events")
		nextGroups, nextTotal, err := store.ListGroups(ctx, 1, 10)
		require.NoError(t, err, "ListGroups must remain readable after rejected writes")
		require.Equal(t, groups, nextGroups, "Rejected writes must leave groups unchanged")
		require.Equal(t, total, nextTotal)
		stored, err := store.GetGroup(ctx, g.ID)
		require.NoError(t, err, "GetGroup must remain readable after rejected replacements")
		require.Equal(t, &g, stored, "A rejected group replacement must leave all stored fields and memberships unchanged")
	})

	t.Run("conditional writes", func(t *testing.T) {
		store := openSQLite(t)
		ctx := t.Context()
		u, err := store.CreateUser(ctx, directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, ExternalID: "subject", UserName: "alice"}, directory.NewAuditEvent(ctx, "create", "subject"))
		require.NoError(t, err, "CreateUser must create the fixture for conditional-write checks")
		g, err := store.CreateGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-ops"}, DisplayName: "ops"}, directory.NewAuditEvent(ctx, "create", "group-ops"))
		require.NoError(t, err, "CreateGroup must create the fixture for conditional-write checks")
		oldUser, oldGroup := u, g
		u, err = store.ReplaceUser(ctx, u, u.Version, directory.NewAuditEvent(ctx, "replace", u.ID))
		require.NoError(t, err, "ReplaceUser must accept the explicit current version")
		g, err = store.ReplaceGroup(ctx, g, g.Version, directory.NewAuditEvent(ctx, "replace", g.ID))
		require.NoError(t, err, "ReplaceGroup must accept the explicit current version")
		_, err = store.ReplaceUser(ctx, u, oldUser.Version, directory.NewAuditEvent(ctx, "replace", u.ID))
		require.ErrorIs(t, err, directory.ErrVersion, "ReplaceUser must return ErrVersion when the supplied version is stale")
		require.ErrorIs(t, store.DeleteUser(ctx, u.ID, oldUser.Version, time.Unix(3, 0), directory.NewAuditEvent(ctx, "delete", u.ID)), directory.ErrVersion, "DeleteUser must return ErrVersion when the supplied version is stale")
		_, err = store.ReplaceGroup(ctx, g, oldGroup.Version, directory.NewAuditEvent(ctx, "replace", g.ID))
		require.ErrorIs(t, err, directory.ErrVersion, "ReplaceGroup must return ErrVersion when the supplied version is stale")
		require.ErrorIs(t, store.DeleteGroup(ctx, g.ID, oldGroup.Version, directory.NewAuditEvent(ctx, "delete", g.ID)), directory.ErrVersion, "DeleteGroup must return ErrVersion when the supplied version is stale")
		gotUser, err := store.GetUser(ctx, u.ID)
		require.NoError(t, err, "GetUser must remain readable after failed conditional writes")
		require.Equal(t, &u, gotUser, "Failed conditional writes must leave the user and its metadata unchanged")
		gotGroup, err := store.GetGroup(ctx, g.ID)
		require.NoError(t, err, "GetGroup must remain readable after failed conditional writes")
		require.Equal(t, &g, gotGroup, "Failed conditional writes must leave the group, memberships, and metadata unchanged")
		missingUser, missingGroup := u, g
		missingUser.ID, missingGroup.ID = "missing", "missing"
		for _, match := range []string{"", "*", u.Version} {
			_, err := store.ReplaceUser(ctx, missingUser, match, directory.NewAuditEvent(ctx, "replace", missingUser.ID))
			require.ErrorIs(t, err, directory.ErrNotFound, "ReplaceUser must return ErrNotFound for a missing resource regardless of match=%q; replacement must not create it", match)
			require.ErrorIs(t, store.DeleteUser(ctx, "missing", match, time.Unix(3, 0), directory.NewAuditEvent(ctx, "delete", "missing")), directory.ErrNotFound, "DeleteUser must return ErrNotFound for a missing resource regardless of match=%q", match)
			_, err = store.ReplaceGroup(ctx, missingGroup, match, directory.NewAuditEvent(ctx, "replace", missingGroup.ID))
			require.ErrorIs(t, err, directory.ErrNotFound, "ReplaceGroup must return ErrNotFound for a missing resource regardless of match=%q; replacement must not create it", match)
			require.ErrorIs(t, store.DeleteGroup(ctx, "missing", match, directory.NewAuditEvent(ctx, "delete", "missing")), directory.ErrNotFound, "DeleteGroup must return ErrNotFound for a missing resource regardless of match=%q", match)
		}
		u, err = store.ReplaceUser(ctx, u, "", directory.NewAuditEvent(ctx, "replace", u.ID))
		require.NoError(t, err, "ReplaceUser without a version precondition must succeed for an existing user")
		g, err = store.ReplaceGroup(ctx, g, "", directory.NewAuditEvent(ctx, "replace", g.ID))
		require.NoError(t, err, "ReplaceGroup without a version precondition must succeed for an existing group")
		require.NoError(t, store.DeleteUser(ctx, u.ID, "", time.Unix(3, 0), directory.NewAuditEvent(ctx, "delete", u.ID)), "DeleteUser with an empty match must delete the existing user without checking its version")
		require.NoError(t, store.DeleteGroup(ctx, g.ID, "", directory.NewAuditEvent(ctx, "delete", g.ID)), "DeleteGroup with an empty match must delete the existing group without checking its version")
	})

	t.Run("concurrent creation preserves one owner of an ID", func(t *testing.T) {
		store := openSQLite(t)
		var wg sync.WaitGroup
		results := make(chan error, 2)
		start := make(chan struct{})
		for _, name := range []string{"alice", "bob"} {
			wg.Go(func() {
				<-start
				_, err := store.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "same-id"}, UserName: name}, directory.NewAuditEvent(t.Context(), "create", "same-id"))
				results <- err
			})
		}
		close(start)
		wg.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			} else {
				require.ErrorIs(t, err, directory.ErrConflict, "A concurrent duplicate ID must fail with ErrConflict")
			}
		}
		require.Equal(t, 1, successes, "Exactly one CreateUser may claim a supplied ID")
		events, _, err := store.Audit(t.Context(), "", 0)
		require.NoError(t, err, "Audit must remain readable after concurrent creation")
		require.Len(t, events, 1, "Rejected duplicate creation must not mutate state or append an audit event")
	})

	t.Run("concurrent same name groups remain distinct", func(t *testing.T) {
		store := openSQLite(t)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for n := range 2 {
			wg.Go(func() {
				_, err := store.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: fmt.Sprintf("group-%d", n)}, DisplayName: "ops", ExternalID: "shared"}, directory.NewAuditEvent(t.Context(), "create", fmt.Sprintf("group-%d", n)))
				errs <- err
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err, "Concurrent CreateGroup calls must both succeed: DisplayName and ExternalID are not unique constraints")
		}
		groups, total, err := store.ListGroups(t.Context(), 1, 10)
		require.NoError(t, err, "ListGroups must succeed after concurrent group creation")
		require.Equal(t, 2, total)
		require.Len(t, groups, 2, "Concurrent CreateGroup calls with the same name must create two distinct groups")
		for _, g := range groups {
			require.Equal(t, "ops", g.DisplayName, "ListGroups must preserve DisplayName after concurrent creation")
			require.Equal(t, "shared", g.ExternalID, "ListGroups must preserve ExternalID after concurrent creation")
		}
		require.Less(t, groups[0].ID, groups[1].ID, "Groups with the same DisplayName must have distinct resource IDs and be ordered by ID")
	})

	for _, kind := range []string{"user", "group"} {
		t.Run(kind+" concurrent conditional replacement", func(t *testing.T) {
			store := openSQLite(t)
			var replace func() error
			if kind == "user" {
				u, err := store.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, UserName: "alice"}, directory.NewAuditEvent(t.Context(), "create", "subject"))
				require.NoError(t, err, "CreateUser must create the fixture for concurrent replacements")
				replace = func() error {
					_, err := store.ReplaceUser(t.Context(), u, u.Version, directory.NewAuditEvent(t.Context(), "replace", u.ID))
					return err
				}
			} else {
				g, err := store.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "group"}, DisplayName: "ops"}, directory.NewAuditEvent(t.Context(), "create", "group"))
				require.NoError(t, err, "CreateGroup must create the fixture for concurrent replacements")
				replace = func() error {
					_, err := store.ReplaceGroup(t.Context(), g, g.Version, directory.NewAuditEvent(t.Context(), "replace", g.ID))
					return err
				}
			}
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			start := make(chan struct{})
			for range 2 {
				wg.Go(func() {
					<-start
					errs <- replace()
				})
			}
			close(start)
			wg.Wait()
			close(errs)
			success := 0
			for err := range errs {
				if err == nil {
					success++
				} else {
					require.ErrorIs(t, err, directory.ErrVersion, "The losing %s replacement must return ErrVersion", kind)
				}
			}
			require.Equal(t, 1, success, "Exactly one of two concurrent %s replacements with the same expectedVersion must succeed", kind)
			history, _, err := store.Audit(t.Context(), "", 0)
			require.NoError(t, err, "Audit must remain readable after concurrent replacements")
			require.Len(t, history, 2, "Only creation and the winning replacement may append audit events")
		})
	}
}
