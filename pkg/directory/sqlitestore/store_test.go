package sqlitestore

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/stretchr/testify/require"
)

func TestRollbackRestartAndCoherentReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	s, e := Open(path)
	require.NoError(t, e)
	u, e := s.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "subject", UserName: "v1", Active: true})
	require.NoError(t, e)
	_, rev, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	// Fail after users/indexes/revision have changed, at the final audit insert.
	_, e = s.db.Exec(`CREATE TRIGGER interrupt BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'interrupted write'); END`)
	require.NoError(t, e)
	_, e = s.ReplaceUser(t.Context(), u.ID, directory.ManagedUser{ExternalID: "new-subject", UserName: "new", Active: false}, "")
	require.Error(t, e)
	actual, actualRev, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	require.Equal(t, rev, actualRev)
	require.Equal(t, "v1", actual.UserName)
	missing, _, e := s.LookupUser(t.Context(), "new-subject")
	require.NoError(t, e)
	require.Nil(t, missing)
	_, e = s.db.Exec("DROP TRIGGER interrupt")
	require.NoError(t, e)
	require.NoError(t, s.Close())
	s, e = Open(path)
	require.NoError(t, e)
	defer s.Close()
	actual, actualRev, e = s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	require.Equal(t, rev, actualRev)
	require.Equal(t, "v1", actual.UserName)
	// Independent connections model another process and must agree on snapshots.
	other, e := Open(path)
	require.NoError(t, e)
	defer other.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Go(func() {
		for n := 2; n <= 40; n++ {
			_, e := s.ReplaceUser(t.Context(), u.ID, directory.ManagedUser{ExternalID: "subject", UserName: fmt.Sprintf("v%d", n), Active: true}, "")
			if e != nil {
				errs <- e
				return
			}
		}
	})
	wg.Go(func() {
		for n := 0; n < 80; n++ {
			u, rev, e := other.LookupUser(t.Context(), "subject")
			if e != nil {
				errs <- e
				return
			}
			_, num, _ := strings.Cut(string(rev), ":")
			version, e := strconv.Atoi(num)
			if e != nil || u.UserName != fmt.Sprintf("v%d", version) {
				errs <- fmt.Errorf("incoherent %v %s", u, rev)
				return
			}
		}
	})
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
}
func TestFirstAliasClaimIsAtomicAcrossConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	a, e := Open(path)
	require.NoError(t, e)
	defer a.Close()
	b, e := Open(path)
	require.NoError(t, e)
	defer b.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, s := range []*Store{a, b} {
		wg.Go(func() {
			_, e := s.CreateGroup(t.Context(), directory.Group{DisplayName: "ops"})
			errs <- e
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	bindings, e := a.Bindings(t.Context())
	require.NoError(t, e)
	require.Len(t, bindings.Groups, 2)
	counts := map[string]int{}
	for _, g := range bindings.Groups {
		counts[g.Status]++
	}
	require.Equal(t, map[string]int{"bound": 1, "conflict": 1}, counts)
}

func TestRebindRejectsChangedAuthorizationSnapshot(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, e)
	defer s.Close()
	admin, e := s.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "admin", UserName: "admin", Active: true})
	require.NoError(t, e)
	first, e := s.CreateGroup(t.Context(), directory.Group{DisplayName: "ops"})
	require.NoError(t, e)
	second, e := s.CreateGroup(t.Context(), directory.Group{DisplayName: "ops"})
	require.NoError(t, e)
	_, authorized, e := s.LookupUser(t.Context(), "admin")
	require.NoError(t, e)
	_, e = s.ReplaceUser(t.Context(), admin.ID, directory.ManagedUser{ExternalID: "admin", UserName: "admin", Active: false}, "")
	require.NoError(t, e)
	snapshot, e := s.Bindings(t.Context())
	require.NoError(t, e)
	require.ErrorIs(t, s.Rebind(t.Context(), "admin", "ops", second.ID, snapshot.Revision, authorized), directory.ErrVersion)
	actual, e := s.Bindings(t.Context())
	require.NoError(t, e)
	require.Equal(t, snapshot, actual)
	for _, g := range actual.Groups {
		if g.ID == first.ID {
			require.Equal(t, "ops", g.Alias)
		}
	}
}

func TestGroupAndDeleteFailuresRollBackProjections(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, e)
	defer s.Close()
	user, e := s.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "subject", UserName: "user", Active: true})
	require.NoError(t, e)
	group := directory.Group{DisplayName: "ops", MemberIDs: []string{user.ID}}
	g, e := s.CreateGroup(t.Context(), group)
	require.NoError(t, e)
	before, rev, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	history, e := s.Audit(t.Context(), 0, 0)
	require.NoError(t, e)
	_, e = s.db.Exec(`CREATE TRIGGER interrupt BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'interrupted write'); END`)
	require.NoError(t, e)
	require.Error(t, s.DeleteUser(t.Context(), user.ID, ""))
	_, e = s.CreateGroup(t.Context(), directory.Group{DisplayName: "uncommitted"})
	require.Error(t, e)
	actual, actualRev, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	require.Equal(t, before, actual)
	require.Equal(t, rev, actualRev)
	persisted, e := s.GetGroup(t.Context(), g.ID)
	require.NoError(t, e)
	require.Equal(t, g, persisted)
	after, e := s.Audit(t.Context(), 0, 0)
	require.NoError(t, e)
	require.Equal(t, history, after)
	snapshot, e := s.Bindings(t.Context())
	require.NoError(t, e)
	require.Len(t, snapshot.Groups, 1)
	_, e = s.db.Exec("DROP TRIGGER interrupt")
	require.NoError(t, e)
	// The schema rejects invalid active values instead of decoding JSON at lookup.
	_, e = s.db.Exec(`UPDATE users SET active=NULL WHERE id=?`, user.ID)
	require.Error(t, e)
	_, e = s.db.Exec(`UPDATE users SET active=2 WHERE id=?`, user.ID)
	require.Error(t, e)
	require.NoError(t, s.Close())
	_, _, e = s.LookupUser(t.Context(), "subject")
	require.Error(t, e)
}

func TestAuditCursorDoesNotSkipEventsSharingARevision(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer s.Close()
	_, err = s.CreateGroup(t.Context(), directory.Group{DisplayName: "ops"})
	require.NoError(t, err)
	first, err := s.Audit(t.Context(), 0, 1)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, "bind", first[0].Action)
	second, err := s.Audit(t.Context(), first[0].Sequence, 1)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, "create", second[0].Action)
	require.Equal(t, first[0].Revision, second[0].Revision)
	require.Greater(t, second[0].Sequence, first[0].Sequence)
	empty, err := s.Audit(t.Context(), second[0].Sequence, 1)
	require.NoError(t, err)
	require.Empty(t, empty)
	// New activity after reaching the end is visible through the same cursor.
	_, err = s.CreateGroup(t.Context(), directory.Group{DisplayName: "dev"})
	require.NoError(t, err)
	next, err := s.Audit(t.Context(), second[0].Sequence, 0)
	require.NoError(t, err)
	require.Len(t, next, 2)
	require.Greater(t, next[0].Sequence, second[0].Sequence)
	for _, limit := range []int{-1, directory.MaxAuditLimit + 1} {
		_, err = s.Audit(t.Context(), 0, limit)
		require.ErrorIs(t, err, directory.ErrInvalid)
	}
}

func TestReadersSeeCommittedSnapshotWhileAnotherConnectionWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	writer, err := Open(path)
	require.NoError(t, err)
	defer writer.Close()
	u, err := writer.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "subject", UserName: "alice", Active: true})
	require.NoError(t, err)
	g, err := writer.CreateGroup(t.Context(), directory.Group{DisplayName: "ops", MemberIDs: []string{u.ID}})
	require.NoError(t, err)
	reader, err := Open(path)
	require.NoError(t, err)
	defer reader.Close()
	_, err = reader.db.Exec("PRAGMA busy_timeout=50")
	require.NoError(t, err)
	before, revision, err := reader.LookupUser(t.Context(), "subject")
	require.NoError(t, err)

	tx, err := writer.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.Exec("UPDATE users SET active=0 WHERE id=?", u.ID)
	require.NoError(t, err)
	_, err = tx.Exec("UPDATE state SET revision=revision+1")
	require.NoError(t, err)
	_, err = tx.Exec("DELETE FROM members WHERE user_id=?", u.ID)
	require.NoError(t, err)
	listed, listingRevision, err := reader.ListUserFacts(t.Context())
	require.NoError(t, err)
	require.Equal(t, []directory.User{*before}, listed)
	require.Equal(t, revision, listingRevision)

	// All public snapshot reads must work while the writer's transaction is open.
	gotUser, err := reader.GetUser(t.Context(), u.ID)
	require.NoError(t, err)
	require.Equal(t, u, gotUser)
	gotGroup, err := reader.GetGroup(t.Context(), g.ID)
	require.NoError(t, err)
	require.Equal(t, g, gotGroup)
	users, total, err := reader.ListUsers(t.Context(), 1, 10)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, []directory.ManagedUser{u}, users)
	groups, total, err := reader.ListGroups(t.Context(), 1, 10)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, []directory.Group{g}, groups)
	facts, gotRevision, err := reader.LookupUser(t.Context(), "subject")
	require.NoError(t, err)
	require.Equal(t, before, facts)
	require.Equal(t, revision, gotRevision)
	bindings, err := reader.Bindings(t.Context())
	require.NoError(t, err)
	require.Equal(t, g.Version, bindings.Revision)
	require.Len(t, bindings.Groups, 1)
	events, err := reader.Audit(t.Context(), 0, 0)
	require.NoError(t, err)
	require.Len(t, events, 3)
}

func TestListUserFactsMatchesAuthorization(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer s.Close()
	empty, rev, err := s.ListUserFacts(t.Context())
	require.NoError(t, err)
	require.Equal(t, []directory.User{}, empty)
	require.NotEmpty(t, rev)
	zed, err := s.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "provider-z", UserName: "zed", Active: false})
	require.NoError(t, err)
	alice, err := s.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "provider-a", UserName: "alice", Active: true, Department: "engineering"})
	require.NoError(t, err)
	_, err = s.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "provider-b", UserName: "bob", Active: true})
	require.NoError(t, err)
	group, err := s.CreateGroup(t.Context(), directory.Group{DisplayName: "wheel", MemberIDs: []string{alice.ID, zed.ID}})
	require.NoError(t, err)
	group.DisplayName = "renamed"
	_, err = s.ReplaceGroup(t.Context(), group.ID, group, "")
	require.NoError(t, err)
	_, err = s.CreateGroup(t.Context(), directory.Group{DisplayName: "wheel", MemberIDs: []string{alice.ID}})
	require.NoError(t, err)
	_, err = s.CreateGroup(t.Context(), directory.Group{DisplayName: "ops", MemberIDs: []string{alice.ID}})
	require.NoError(t, err)
	users, revision, err := s.ListUserFacts(t.Context())
	require.NoError(t, err)
	require.Len(t, users, 3)
	require.Equal(t, []string{"alice", "bob", "zed"}, []string{users[0].UserName, users[1].UserName, users[2].UserName})
	require.Equal(t, "provider-a", users[0].ID)
	require.NotEqual(t, alice.ID, users[0].ID)
	require.Equal(t, []string{"ops", "wheel"}, users[0].Groups)
	require.Empty(t, users[1].Groups)
	require.False(t, users[2].Active)
	for _, user := range users {
		fact, lookupRevision, err := s.LookupUser(t.Context(), user.ID)
		require.NoError(t, err)
		require.Equal(t, user, *fact)
		require.Equal(t, revision, lookupRevision)
	}
	users[0].Groups[0] = "mutated"
	again, _, err := s.ListUserFacts(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"ops", "wheel"}, again[0].Groups)
	require.NoError(t, s.Close())
	_, _, err = s.ListUserFacts(t.Context())
	require.Error(t, err, "storage errors must not produce an empty listing")
}
