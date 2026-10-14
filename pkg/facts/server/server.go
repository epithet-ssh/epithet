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

// DirectoryOption configures optional directory management.
type DirectoryOption func(*directoryOptions)
type directoryOptions struct{ managed directory.Store }

// WithDirectoryManagement adds SCIM and managed directory operations. The data
// source and management implementation must describe the same logical directory;
// they may be separate instances. The caller owns both lifetimes.
func WithDirectoryManagement(managed directory.Store) DirectoryOption {
	return func(options *directoryOptions) { options.managed = managed }
}

// DirectoryHandler serves directory facts and the existing read-only actor and
// user-list operations. Management is opt-in, even when users also implements
// Store. An empty control key disables all private control routes.
func DirectoryHandler(users directory.Directory, caKey, controlKey sshcert.RawPublicKey, options ...DirectoryOption) (http.Handler, error) {
	var config directoryOptions
	for _, option := range options {
		option(&config)
	}
	return serviceHandler(users, nil, &backend{Directory: users, ManagedDirectory: config.managed}, caKey, controlKey, []string{"/manage", "/actor", "/scim/v2/", "OPTIONS /lookup"})
}

// InventoryOption configures optional inventory management.
type InventoryOption func(*inventoryOptions)
type inventoryOptions struct{ managed inventory.Store }

// WithInventoryManagement adds the inventory management API. The data source
// and management implementation must describe the same logical inventory;
// they may be separate instances. The caller owns both lifetimes.
func WithInventoryManagement(managed inventory.Store) InventoryOption {
	return func(options *inventoryOptions) { options.managed = managed }
}

// InventoryHandler serves inventory facts. Management is opt-in, even when hosts
// also implements Store. An empty control key disables management; the CA reader
// key never confers mutation authority. The caller owns the source's lifetime.
func InventoryHandler(hosts inventory.Hosts, caKey, controlKey sshcert.RawPublicKey, options ...InventoryOption) (http.Handler, error) {
	var config inventoryOptions
	for _, option := range options {
		option(&config)
	}
	lookup, err := LookupHandler(nil, hosts, caKey, controlKey)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	if config.managed != nil && controlKey != "" {
		management, err := inventoryHandler(config.managed, controlKey)
		if err != nil {
			return nil, err
		}
		mux.Handle("OPTIONS /lookup", management)
		mux.Handle("/inventory/", management)
	}
	mux.Handle("/lookup", lookup)
	return mux, nil
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
