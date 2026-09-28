package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/controlplane"
	"github.com/epithet-ssh/epithet/pkg/factservice"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type InventoryCLI struct {
	ManagementCLI `embed:""`

	InventoryMode string              `help:"Host inventory mode: static files only, or enrollment with optional static files" name:"inventory-mode" default:"enrollment" enum:"static,enrollment"`
	StateDir      string              `help:"Shared root for inventory/ and directory/ storage (default: native system state directory)" name:"state-dir"`
	Serve         InventoryServeCLI   `cmd:"" default:"withargs" help:"Serve directory and inventory"`
	List          InventoryListCLI    `cmd:"list" aliases:"l,li,lis" help:"List static and dynamic host records"`
	Show          InventoryShowCLI    `cmd:"show" aliases:"s,sh,show" help:"Show one host record"`
	Edit          InventoryEditCLI    `cmd:"edit" aliases:"e,ed,edi" help:"Edit a dynamic host in EDITOR"`
	Approve       InventoryApproveCLI `cmd:"approve" aliases:"a,ap,app" help:"Review, edit, approve, or deny enrollment"`
	Remove        InventoryRemoveCLI  `cmd:"remove" help:"Withdraw a dynamic host from inventory"`
	Token         InventoryTokenCLI   `cmd:"token" help:"Create, list, or revoke enrollment tokens"`
	Audit         InventoryAuditCLI   `cmd:"audit" help:"Show durable inventory mutation audit"`

	Listen        string   `help:"Address to listen on" short:"l" default:"127.0.0.1:9998"`
	ControlPubkey string   `help:"Control service public key for administration" name:"control-public-key"`
	CAPubkey      string   `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-public-key"`
	Static        []string `help:"Static inventory file path or glob (repeatable; optional in enrollment mode)" name:"inventory-static-file"`
	PrincipalMode string   `help:"Default host principal mode" name:"principal-mode" default:"epithet-principal-v1" enum:"account-name,epithet-principal-v1"`
	Check         bool     `help:"Validate inventory files, then exit" name:"check"`
}

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

// Resolve paths only for enabled stores; static mode never opens managed state.
func serviceStatePath(root string, elements ...string) (string, error) {
	var err error
	if root == "" {
		root, err = config.SystemStateDir()
	} else {
		root, err = expandPath(root)
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{root}, elements...)...), nil
}
