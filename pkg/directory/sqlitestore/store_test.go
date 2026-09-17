package sqlitestore

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/directory/scim"
	"github.com/stretchr/testify/require"
)

func doc(s string) scim.Document {
	var d scim.Document
	if e := json.Unmarshal([]byte(s), &d); e != nil {
		panic(e)
	}
	return d
}
func TestRollbackRestartAndCoherentReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	s, e := Open(path)
	require.NoError(t, e)
	u, e := s.Create(t.Context(), scim.Users, doc(`{"externalId":"subject","userName":"v1","active":true}`))
	require.NoError(t, e)
	_, rev, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	// Fail after resources/indexes/revision have changed, at the final audit insert.
	_, e = s.db.Exec(`CREATE TRIGGER interrupt BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'interrupted write'); END`)
	require.NoError(t, e)
	_, e = s.Replace(t.Context(), scim.Users, u.ID, doc(`{"externalId":"new-subject","userName":"new","active":false}`), "")
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
			_, e := s.Replace(t.Context(), scim.Users, u.ID, doc(fmt.Sprintf(`{"externalId":"subject","userName":"v%d","active":true}`, n)), "")
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
			_, e := s.Create(t.Context(), scim.Groups, doc(`{"displayName":"ops","members":[]}`))
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
	admin, e := s.Create(t.Context(), scim.Users, doc(`{"externalId":"admin","userName":"admin","active":true}`))
	require.NoError(t, e)
	first, e := s.Create(t.Context(), scim.Groups, doc(`{"displayName":"ops","members":[]}`))
	require.NoError(t, e)
	second, e := s.Create(t.Context(), scim.Groups, doc(`{"displayName":"ops","members":[]}`))
	require.NoError(t, e)
	_, authorized, e := s.LookupUser(t.Context(), "admin")
	require.NoError(t, e)
	_, e = s.Replace(t.Context(), scim.Users, admin.ID, doc(`{"externalId":"admin","userName":"admin","active":false}`), "")
	require.NoError(t, e)
	snapshot, e := s.Bindings(t.Context())
	require.NoError(t, e)
	require.ErrorIs(t, s.Rebind(t.Context(), "admin", "ops", second.ID, snapshot.Revision, authorized), scim.ErrVersion)
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
	user, e := s.Create(t.Context(), scim.Users, doc(`{"externalId":"subject","userName":"user","active":true}`))
	require.NoError(t, e)
	groupDoc := doc(fmt.Sprintf(`{"displayName":"ops","members":[{"value":%q}]}`, user.ID))
	g, e := s.Create(t.Context(), scim.Groups, groupDoc)
	require.NoError(t, e)
	before, rev, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	history, e := s.Audit(t.Context())
	require.NoError(t, e)
	_, e = s.db.Exec(`CREATE TRIGGER interrupt BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'interrupted write'); END`)
	require.NoError(t, e)
	require.Error(t, s.Delete(t.Context(), scim.Users, user.ID, ""))
	_, e = s.Create(t.Context(), scim.Groups, doc(`{"displayName":"uncommitted","members":[]}`))
	require.Error(t, e)
	actual, actualRev, e := s.LookupUser(t.Context(), "subject")
	require.NoError(t, e)
	require.Equal(t, before, actual)
	require.Equal(t, rev, actualRev)
	persisted, e := s.Get(t.Context(), scim.Groups, g.ID)
	require.NoError(t, e)
	require.Equal(t, g, persisted)
	after, e := s.Audit(t.Context())
	require.NoError(t, e)
	require.Equal(t, history, after)
	snapshot, e := s.Bindings(t.Context())
	require.NoError(t, e)
	require.Len(t, snapshot.Groups, 1)
	_, e = s.db.Exec("DROP TRIGGER interrupt")
	require.NoError(t, e)
	_, e = s.db.Exec(`UPDATE resources SET document='{"externalId":"subject","userName":"user","active":null}' WHERE id=?`, user.ID)
	require.NoError(t, e)
	_, _, e = s.LookupUser(t.Context(), "subject")
	require.ErrorContains(t, e, "active status")
	require.NoError(t, s.Close())
	_, _, e = s.LookupUser(t.Context(), "subject")
	require.Error(t, e)
}
