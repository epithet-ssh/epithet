// Package server serves built-in directory and inventory facts and their private
// management APIs. It authenticates service keys; public user authentication and
// administrative authorization belong to the control plane. Stores retain
// ownership of mutation invariants, transactions, and audit records.
package server

import (
	"net/http"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// DirectoryHandler assembles directory lookup and private control routes. users
// supplies facts and actor snapshots; managed, when nonnil, supplies mutations
// and SCIM provisioning. An empty control key disables all private control routes.
// The caller owns the sources and their lifetime.
func DirectoryHandler(users directory.Directory, managed directory.Store, caKey, controlKey sshcert.RawPublicKey) (http.Handler, error) {
	return serviceHandler(users, nil, &backend{Directory: users, ManagedDirectory: managed}, caKey, controlKey, []string{"/manage", "/actor", "/scim"})
}

// InventoryHandler assembles managed inventory lookup and private control routes.
// An empty control key disables management. The caller owns the store and its
// lifetime; the CA reader key never confers mutation authority.
func InventoryHandler(store inventory.Store, caKey, controlKey sshcert.RawPublicKey) (http.Handler, error) {
	var hosts inventory.Hosts
	if store != nil {
		hosts = store
	}
	return serviceHandler(nil, hosts, &backend{Store: store}, caKey, controlKey, []string{"/manage"})
}

func serviceHandler(users directory.Directory, hosts inventory.Hosts, control *backend, caKey, controlKey sshcert.RawPublicKey, paths []string) (http.Handler, error) {
	lookup, err := LookupHandler(users, hosts, caKey, controlKey)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/lookup", lookup)
	if controlKey != "" {
		handler, err := control.handler(controlKey)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			mux.Handle(path, handler)
		}
	}
	return mux, nil
}
