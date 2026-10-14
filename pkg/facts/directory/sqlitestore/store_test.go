package sqlitestore

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/stretchr/testify/require"
)

func TestRollbackRestartAndCoherentReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	s, e := Open(path)
	require.NoError(t, e)
	u, e := s.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, ExternalID: "subject", UserName: "v1", Department: "v1", Active: true}, directory.NewAuditEvent(t.Context(), "create", "subject"))
	require.NoError(t, e)
	_, e = s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	// Fail after users/indexes/revision have changed, at the final audit insert.
	_, e = s.db.Exec(`CREATE TRIGGER interrupt BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'interrupted write'); END`)
	require.NoError(t, e)
	_, e = s.ReplaceUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: u.ID}, ExternalID: "new-subject", UserName: "new", Active: false}, "", directory.NewAuditEvent(t.Context(), "replace", u.ID))
	require.Error(t, e)
	actual, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)

	require.Equal(t, "v1", actual.UserName)
	missing, e := s.LookupUser(t.Context(), "new-subject")
	require.NoError(t, e)
	require.Nil(t, missing)
	_, e = s.db.Exec("DROP TRIGGER interrupt")
	require.NoError(t, e)
	require.NoError(t, s.Close())
	s, e = Open(path)
	require.NoError(t, e)
	defer s.Close()
	actual, e = s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)

	require.Equal(t, "v1", actual.UserName)
	// Independent connections model another process and must agree on snapshots.
	other, e := Open(path)
	require.NoError(t, e)
	defer other.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Go(func() {
		for n := 2; n <= 40; n++ {
			_, e := s.ReplaceUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: u.ID}, ExternalID: "subject", UserName: fmt.Sprintf("v%d", n), Department: fmt.Sprintf("v%d", n), Active: true}, "", directory.NewAuditEvent(t.Context(), "replace", u.ID))
			if e != nil {
				errs <- e
				return
			}
		}
	})
	wg.Go(func() {
		for n := 0; n < 80; n++ {
			u, e := other.LookupUser(t.Context(), "subject")
			if e != nil {
				errs <- e
				return
			}
			if u == nil || u.UserName != u.Department {
				errs <- fmt.Errorf("incoherent user: %v", u)
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
func TestGroupAndDeleteFailuresRollBackProjections(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, e)
	defer s.Close()
	user, e := s.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, ExternalID: "subject", UserName: "user", Active: true}, directory.NewAuditEvent(t.Context(), "create", "subject"))
	require.NoError(t, e)
	group := directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-ops"}, DisplayName: "ops", MemberIDs: []string{user.ID}}
	g, e := s.CreateGroup(t.Context(), group, directory.NewAuditEvent(t.Context(), "create", group.ID))
	require.NoError(t, e)
	before, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	history, _, e := s.Audit(t.Context(), "", 0)
	require.NoError(t, e)
	_, e = s.db.Exec(`CREATE TRIGGER interrupt BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'interrupted write'); END`)
	require.NoError(t, e)
	require.Error(t, s.DeleteUser(t.Context(), user.ID, "", time.Unix(3, 0), directory.NewAuditEvent(t.Context(), "delete", user.ID)))
	_, e = s.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-uncommitted"}, DisplayName: "uncommitted"}, directory.NewAuditEvent(t.Context(), "create", "group-uncommitted"))
	require.Error(t, e)
	actual, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	require.Equal(t, before, actual)

	persisted, e := s.GetGroup(t.Context(), g.ID)
	require.NoError(t, e)
	require.Equal(t, &g, persisted)
	after, _, e := s.Audit(t.Context(), "", 0)
	require.NoError(t, e)
	require.Equal(t, history, after)
	groups, total, e := s.ListGroups(t.Context(), 1, 10)
	require.NoError(t, e)
	require.Len(t, groups, 1)
	require.Equal(t, 1, total)
	_, e = s.db.Exec("DROP TRIGGER interrupt")
	require.NoError(t, e)
	// The schema rejects invalid active values instead of decoding JSON at lookup.
	_, e = s.db.Exec(`UPDATE users SET active=NULL WHERE id=?`, user.ID)
	require.Error(t, e)
	_, e = s.db.Exec(`UPDATE users SET active=2 WHERE id=?`, user.ID)
	require.Error(t, e)
	require.NoError(t, s.Close())
	_, e = s.LookupUser(t.Context(), "subject")
	require.Error(t, e)
	_, e = s.GetUser(t.Context(), "missing")
	require.Error(t, e, "GetUser must not report absence when storage is unavailable")
	_, e = s.GetGroup(t.Context(), "missing")
	require.Error(t, e, "GetGroup must not report absence when storage is unavailable")
}

func TestAuditCursorDoesNotSkipEventsSharingATimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	s, err := Open(path)
	require.NoError(t, err)
	event := directory.NewAuditEvent(t.Context(), "create", "group-ops")
	_, err = s.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-ops"}, DisplayName: "ops"}, event)
	require.NoError(t, err)
	_, err = s.db.Exec(`INSERT INTO audit (time,actor,action,resource_id,alias,previous_id) SELECT time,actor,'bind',resource_id,'ops','' FROM audit LIMIT 1`)
	require.NoError(t, err)
	first, cursor, err := s.Audit(t.Context(), "", 1)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, "create", first[0].Action)
	require.NotEmpty(t, cursor)
	require.NoError(t, s.Close())
	s, err = Open(path)
	require.NoError(t, err)
	defer s.Close()
	second, next, err := s.Audit(t.Context(), cursor, 1)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, "bind", second[0].Action)
	require.Equal(t, first[0].Time, second[0].Time)
	require.Empty(t, next)
	for _, limit := range []int{-1, directory.MaxAuditLimit + 1} {
		_, _, err := s.Audit(t.Context(), "", limit)
		require.ErrorIs(t, err, directory.ErrInvalid)
	}
}

func TestReadersSeeCommittedSnapshotWhileAnotherConnectionWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	writer, err := Open(path)
	require.NoError(t, err)
	defer writer.Close()
	u, err := writer.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, ExternalID: "subject", UserName: "alice", Active: true}, directory.NewAuditEvent(t.Context(), "create", "subject"))
	require.NoError(t, err)
	g, err := writer.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-ops"}, DisplayName: "ops", MemberIDs: []string{u.ID}}, directory.NewAuditEvent(t.Context(), "create", "group-ops"))
	require.NoError(t, err)
	reader, err := Open(path)
	require.NoError(t, err)
	defer reader.Close()
	_, err = reader.db.Exec("PRAGMA busy_timeout=50")
	require.NoError(t, err)
	before, err := reader.LookupUser(t.Context(), "subject")
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

	// All public snapshot reads must work while the writer's transaction is open.
	gotUser, err := reader.GetUser(t.Context(), u.ID)
	require.NoError(t, err)
	require.Equal(t, &u, gotUser)
	gotGroup, err := reader.GetGroup(t.Context(), g.ID)
	require.NoError(t, err)
	require.Equal(t, &g, gotGroup)
	users, total, err := reader.ListUsers(t.Context(), 1, 10)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, []directory.ManagedUser{u}, users)
	groups, total, err := reader.ListGroups(t.Context(), 1, 10)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, []directory.ManagedGroup{g}, groups)
	facts, err := reader.LookupUser(t.Context(), "subject")
	require.NoError(t, err)
	require.Equal(t, before, facts)

	events, _, err := reader.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Len(t, events, 2)
}
