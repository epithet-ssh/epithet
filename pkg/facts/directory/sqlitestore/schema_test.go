package sqlitestore

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/stretchr/testify/require"
)

func TestCreateAndReopenCurrentSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	s, err := Open(path)
	require.NoError(t, err)
	var version, aliases int
	require.NoError(t, s.db.QueryRow("PRAGMA user_version").Scan(&version))
	require.Equal(t, 4, version)
	require.NoError(t, s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='aliases'").Scan(&aliases))
	require.Zero(t, aliases)
	user, err := s.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, ExternalID: "subject", UserName: "alice", Active: true}, directory.NewAuditEvent(t.Context(), "create", "subject"))
	require.NoError(t, err)
	require.NoError(t, s.Close())

	s, err = Open(path)
	require.NoError(t, err)
	defer s.Close()
	actual, err := s.GetUser(t.Context(), user.ID)
	require.NoError(t, err)
	require.Equal(t, &user, actual)

}

func TestRejectOtherSchemaVersionsWithoutChangingData(t *testing.T) {
	for _, version := range []int{1, 2, 3, 5} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "directory.db")
			db, err := sql.Open("sqlite", path)
			require.NoError(t, err)
			defer db.Close()
			_, err = db.Exec(`CREATE TABLE aliases (name TEXT PRIMARY KEY, group_id TEXT NOT NULL UNIQUE);
INSERT INTO aliases VALUES ('ops', 'group-id');`)
			require.NoError(t, err)
			_, err = db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version))
			require.NoError(t, err)

			s, err := Open(path)
			require.Nil(t, s)
			require.ErrorContains(t, err, fmt.Sprintf("unsupported directory database version %d", version))
			var actual int
			require.NoError(t, db.QueryRow("PRAGMA user_version").Scan(&actual))
			require.Equal(t, version, actual)
			var name, id string
			require.NoError(t, db.QueryRow("SELECT name, group_id FROM aliases").Scan(&name, &id))
			require.Equal(t, "ops", name)
			require.Equal(t, "group-id", id)
			require.NoError(t, db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&actual))
			require.Equal(t, 1, actual)
		})
	}
}
