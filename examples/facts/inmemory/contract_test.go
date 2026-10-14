package inmemory

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	dirtest "github.com/epithet-ssh/epithet/pkg/facts/directory/storetest"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	invtest "github.com/epithet-ssh/epithet/pkg/facts/inventory/storetest"
)

func TestDirectoryStoreContract(t *testing.T) {
	dirtest.Run(t, func(t *testing.T) dirtest.Backend {
		store := &memDir{
			users:     make(map[string]directory.ManagedUser),
			groups:    make(map[string]directory.ManagedGroup),
			userNames: make(map[string]directory.ManagedUser),
		}
		return dirtest.Backend{Directory: store, Store: store}
	})
}

func TestInventoryStoreContract(t *testing.T) {
	invtest.Run(t, func(t *testing.T) invtest.Backend {
		store := &memInv{
			hosts: make(map[string]inventory.Host),
		}
		return invtest.Backend{
			Hosts: store,
			Store: store,
		}
	})
}
