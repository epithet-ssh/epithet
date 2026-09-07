package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// InventoryOIDCConfig holds OIDC configuration for the inventory server.
type InventoryOIDCConfig struct {
	IdentityMode oidc.IdentityMode `help:"Inventory identity mode: stable-id (default) or verified-email" name:"identity-mode" env:"EPITHET_INVENTORY_OIDC_IDENTITY_MODE"`
	UserIDClaim  string            `help:"JWT claim mapped to inventory id in stable-id mode, including email without verification checks (default: oid for Microsoft Entra, sub otherwise)" name:"user-id-claim" env:"EPITHET_INVENTORY_OIDC_USER_ID_CLAIM"`
	Issuer       string            `help:"OIDC issuer URL" name:"issuer"`
	ClientID     string            `help:"OIDC client ID" name:"client-id"`
	ClientSecret string            `help:"OIDC client secret (for confidential clients)" name:"client-secret"`
}

type InventoryCLI struct {
	Listen        string              `help:"Address to listen on" short:"l" default:"127.0.0.1:9998"`
	CAPubkey      string              `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-pubkey"`
	OIDC          InventoryOIDCConfig `embed:"" prefix:"oidc-"`
	Static        []string            `help:"Static inventory file path or glob (repeatable)" name:"static"`
	PrincipalMode string              `help:"Default host principal mode" name:"principal-mode" default:"account-name" enum:"account-name,epithet-principal-v1"`
	Check         bool                `help:"Validate inventory files, then exit" name:"check"`
}

func (c *InventoryCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	if _, _, err := oidc.ResolveIdentity(c.OIDC.Issuer, c.OIDC.IdentityMode, c.OIDC.UserIDClaim); err != nil {
		return fmt.Errorf("invalid OIDC identity configuration: %w", err)
	}
	paths, err := config.ExpandGlobs(c.Static)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no inventory files match %s", strings.Join(c.Static, ", "))
	}
	inv, err := inventory.NewStatic(paths, inventory.WithDefaultPrincipalMode(inventory.PrincipalMode(c.PrincipalMode)))
	if err != nil {
		return err
	}
	if c.Check {
		fmt.Println("inventory OK")
		return nil
	}
	if c.CAPubkey == "" {
		return fmt.Errorf("inventory.ca-pubkey is required")
	}
	key, err := resolveCAPubkey(c.CAPubkey, tlsCfg, logger)
	if err != nil {
		return err
	}
	resolver := &inventoryserver.Resolver{Directory: inv, Hosts: inv, DirectoryRevision: inv.DirectoryRevision(), InventoryRevision: inv.InventoryRevision()}
	serverCfg := &inventoryserver.ServerConfig{CAPublicKey: key, OIDC: inventoryserver.OIDCConfig{
		Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, ClientSecret: c.OIDC.ClientSecret,
		IdentityMode: c.OIDC.IdentityMode, UserIDClaim: c.OIDC.UserIDClaim,
	}}
	if err := serverCfg.Validate(); err != nil {
		return err
	}
	validator, err := oidc.NewValidator(context.Background(), oidc.Config{
		Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, IdentityMode: c.OIDC.IdentityMode, UserIDClaim: c.OIDC.UserIDClaim, TLSConfig: tlsCfg,
	})
	if err != nil {
		return fmt.Errorf("creating inventory OIDC validator: %w", err)
	}
	auth := serverCfg.BootstrapAuth()
	handler, err := inventoryserver.NewHandler(inventoryserver.Config{CAPublicKey: sshcert.RawPublicKey(key), Resolver: resolver, Validator: validator, Discovery: &wire.Discovery{Auth: &auth}})
	if err != nil {
		return err
	}
	logger.Info("starting inventory server", "listen", c.Listen, "files", len(paths), "directoryRevision", inv.DirectoryRevision(), "inventoryRevision", inv.InventoryRevision())
	return listenAndServe(c.Listen, handler)
}
