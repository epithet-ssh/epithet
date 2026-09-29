package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/controlplane"
	"github.com/epithet-ssh/epithet/pkg/factservice"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type InventoryServeCLI struct{}

func (_ *InventoryServeCLI) Run(c *InventoryCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	return c.runServer(logger, tlsCfg)
}

func (c *InventoryCLI) runServer(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	if c.InventoryMode != "" && c.InventoryMode != "static" && c.InventoryMode != "enrollment" {
		return fmt.Errorf("unknown inventory-mode %q", c.InventoryMode)
	}
	paths, err := config.ExpandGlobs(c.Static)
	if err != nil {
		return err
	}
	if len(paths) == 0 && (len(c.Static) > 0 || c.InventoryMode == "static") {
		return fmt.Errorf("no inventory files match %s", strings.Join(c.Static, ", "))
	}
	mode := inventory.PrincipalMode(c.PrincipalMode)
	if mode == "" {
		mode = inventory.EpithetPrincipalV1
	}
	// Managed inventory can run without a static fallback.
	var inv *inventory.Static
	if len(paths) > 0 {
		inv, err = inventory.NewStatic(paths, inventory.WithDefaultPrincipalMode(mode), inventory.WithoutUsers())
		if err != nil {
			return err
		}
	}
	var hosts inventory.Hosts = inv
	var managed *inventory.Managed
	if c.InventoryMode != "static" {
		dir, err := serviceStatePath(c.StateDir, "inventory")
		if err != nil {
			return err
		}
		managed, err = inventory.OpenManaged(dir, inv)
		if err != nil {
			return err
		}
		defer managed.Close()
		hosts = managed
	}
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
	handler, err := factservice.Handler(nil, hosts, sshcert.RawPublicKey(key), sshcert.RawPublicKey(controlKey))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/lookup", handler)
	if controlKey != "" {
		backend, err := (&controlplane.Backend{Store: managed}).Handler(sshcert.RawPublicKey(controlKey))
		if err != nil {
			return err
		}
		mux.Handle("/manage", backend)
	}
	logger.Info("starting inventory server", "listen", c.Listen)
	return listenAndServe(c.Listen, mux)
}
