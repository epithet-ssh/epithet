package main

import (
	"fmt"
	"log/slog"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type DirectoryServeCLI struct{}

func (*DirectoryServeCLI) Run(c *DirectoryCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	var users directory.Directory
	var store directory.Store
	switch c.Mode {
	case "", "static":
		paths, err := config.ExpandGlobs(c.Static)
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			return fmt.Errorf("no static directory files matched")
		}
		// Static directory loading ignores host-specific configuration.
		inv, err := directory.NewStatic(paths)
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
		return fmt.Errorf("unknown directory-mode %q", c.Mode)
	}
	if c.Check {
		fmt.Println("directory OK")
		return nil
	}
	if c.CAPubkey == "" {
		return fmt.Errorf("--ca-public-key is required")
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
	handler, err := factserver.DirectoryHandler(users, store, sshcert.RawPublicKey(key), sshcert.RawPublicKey(controlKey))
	if err != nil {
		return err
	}
	logger.Info("starting directory server", "listen", c.Listen)
	return listenAndServe(c.Listen, handler)
}
