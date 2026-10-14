package sqlitestore_test

import (
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/storetest"
	"github.com/stretchr/testify/require"
)

func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Backend {
		store := openSQLite(t)
		return storetest.Backend{Directory: store, Store: store}
	})
}

func openSQLite(t *testing.T) *sqlitestore.Store {
	t.Helper()
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store
}
