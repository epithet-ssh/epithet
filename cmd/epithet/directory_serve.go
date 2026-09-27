package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/controlplane"
	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/factservice"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type DirectoryServeCLI struct{}

func (*DirectoryServeCLI) Run(c *DirectoryCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	var users directory.Directory
	var store directory.Store
	switch c.Source {
	case "", "static":
		paths, err := config.ExpandGlobs(c.Static)
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			return fmt.Errorf("no static directory files matched")
		}
		// Static inventory's user projection ignores host-specific configuration.
		inv, err := inventory.NewStatic(paths, inventory.WithoutHosts())
		if err != nil {
			return err
		}
		users = inv
	case "scim":
		path, err := serviceStatePath(c.StateDir, "directory", "directory.db")
		if err != nil {
			return err
		}
		store, err = sqlitestore.Open(path)
		if err != nil {
			return err
		}
		defer store.Close()
		users = store
	default:
		return fmt.Errorf("unknown directory source %q", c.Source)
	}
	if c.Check {
		fmt.Println("directory OK")
		return nil
	}
	if c.CAPubkey == "" {
		return fmt.Errorf("directory.ca-pubkey is required")
	}
	key, err := resolveCAPubkey(c.CAPubkey, tlsCfg, logger)
	if err != nil {
		return err
	}
	var controlKey string
	if c.ControlPubkey != "" {
		controlKey, err = resolveCAPubkey(c.ControlPubkey, tlsCfg, logger)
		if err != nil {
			return err
		}
	}
	facts, err := factservice.Handler(users, nil, sshcert.RawPublicKey(key), sshcert.RawPublicKey(controlKey))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/lookup", facts)
	if controlKey != "" {
		backend, err := (&controlplane.Backend{Directory: users, ManagedDirectory: store}).Handler(sshcert.RawPublicKey(controlKey))
		if err != nil {
			return err
		}
		for _, path := range []string{"/manage", "/actor", "/scim"} {
			mux.Handle(path, backend)
		}
	}
	logger.Info("starting directory server", "listen", c.Listen)
	return listenAndServe(c.Listen, mux)
}
