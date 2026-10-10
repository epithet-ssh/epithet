package main

import (
	"fmt"
	"log/slog"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type InventoryServeCLI struct{}

func (_ *InventoryServeCLI) Run(c *InventoryCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	return c.runServer(logger, tlsCfg)
}

func (c *InventoryCLI) runServer(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	path, err := serviceStatePath(c.StateDir, "inventory", "inventory.db")
	if err != nil {
		return err
	}
	managed, err := inventory.OpenManaged(path)
	if err != nil {
		return err
	}
	defer managed.Close()
	if c.Check {
		fmt.Println("inventory OK")
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
	handler, err := factserver.InventoryHandler(managed, sshcert.RawPublicKey(key), sshcert.RawPublicKey(controlKey))
	if err != nil {
		return err
	}
	logger.Info("starting inventory server", "listen", c.Listen)
	return listenAndServe(c.Listen, handler)
}
