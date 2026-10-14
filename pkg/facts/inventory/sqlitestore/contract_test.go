package sqlitestore_test

import (
	"github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory/storetest"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Backend {
		path := filepath.Join(t.TempDir(), "inventory.db")
		store, err := sqlitestore.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { store.Close() })
		return storetest.Backend{Hosts: store, Store: store}
	})
}
