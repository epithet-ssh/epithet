package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/directory/scim"
	"github.com/epithet-ssh/epithet/pkg/directory/sqlitestore"
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
	ManagementCLI `embed:""`

	DirectorySource string              `help:"Authoritative user directory: static or scim" name:"directory-source" default:"static" enum:"static,scim"`
	SCIMToken       string              `help:"Literal SCIM provisioning bearer token (alternative to scim-token-file)" name:"scim-token"`
	SCIMTokenFile   string              `help:"File containing the operator-supplied SCIM provisioning bearer token" name:"scim-token-file"`
	InventorySource string              `help:"Host inventory: static or managed (static files plus enrolled hosts)" name:"inventory-source" default:"static" enum:"static,managed"`
	StateDir        string              `help:"Shared root for inventory/ and directory/ storage (default: native system state directory)" name:"state-dir"`
	AdminUsers      []string            `help:"Directory user ID granted inventory-admin (repeatable)" name:"admin-user"`
	AdminGroups     []string            `help:"Directory group granted inventory-admin (repeatable)" name:"admin-group"`
	Serve           InventoryServeCLI   `cmd:"" default:"withargs" help:"Serve directory and inventory"`
	List            InventoryListCLI    `cmd:"list" aliases:"l,li,lis" help:"List static and dynamic host records"`
	Show            InventoryShowCLI    `cmd:"show" aliases:"s,sh,show" help:"Show one host record"`
	Edit            InventoryEditCLI    `cmd:"edit" aliases:"e,ed,edi" help:"Edit a dynamic host in EDITOR"`
	Approve         InventoryApproveCLI `cmd:"approve" aliases:"a,ap,app" help:"Review, edit, approve, or deny enrollment"`
	Remove          InventoryRemoveCLI  `cmd:"remove" help:"Withdraw a dynamic host from inventory"`
	Token           InventoryTokenCLI   `cmd:"token" help:"Create, list, or revoke enrollment tokens"`
	Audit           InventoryAuditCLI   `cmd:"audit" help:"Show durable inventory mutation audit"`

	Listen        string              `help:"Address to listen on" short:"l" default:"127.0.0.1:9998"`
	CAPubkey      string              `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-pubkey"`
	OIDC          InventoryOIDCConfig `embed:"" prefix:"oidc-"`
	Static        []string            `help:"Static inventory file path or glob (repeatable)" name:"static"`
	PrincipalMode string              `help:"Default host principal mode" name:"principal-mode" default:"account-name" enum:"account-name,epithet-principal-v1"`
	Check         bool                `help:"Validate inventory files, then exit" name:"check"`
}

type InventoryServeCLI struct{}

func (_ *InventoryServeCLI) Run(c *InventoryCLI, logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	return c.runServer(logger, tlsCfg)
}
func (c *InventoryCLI) runServer(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	if c.InventorySource != "" && c.InventorySource != "static" && c.InventorySource != "managed" {
		return fmt.Errorf("unknown inventory-source %q", c.InventorySource)
	}
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
	options := []inventory.StaticOption{inventory.WithDefaultPrincipalMode(inventory.PrincipalMode(c.PrincipalMode))}
	if c.DirectorySource == "scim" {
		options = append(options, inventory.WithoutUsers())
	}
	inv, err := inventory.NewStatic(paths, options...)
	if err != nil {
		return err
	}
	var users directory.Directory = inv
	var directoryStore scim.Store
	var scimHandler http.Handler
	switch c.DirectorySource {
	case "", "static": // Static recovery does not even open the managed database or secret.
	case "scim":
		dbPath, e := serviceStatePath(c.StateDir, "directory", "directory.db")
		if e != nil {
			return e
		}
		if c.SCIMToken != "" && c.SCIMTokenFile != "" {
			return fmt.Errorf("use either scim-token or scim-token-file")
		}
		if c.SCIMToken == "" && c.SCIMTokenFile == "" {
			return fmt.Errorf("SCIM directory requires scim-token or scim-token-file")
		}
		secret := c.SCIMToken
		if c.SCIMTokenFile != "" {
			tokenPath, e := expandPath(c.SCIMTokenFile)
			if e != nil {
				return e
			}
			data, e := os.ReadFile(tokenPath)
			if e != nil {
				return fmt.Errorf("reading SCIM token file: %w", e)
			}
			secret = strings.TrimSpace(string(data))
		}
		directoryStore, err = sqlitestore.Open(dbPath)
		if err != nil {
			return err
		}
		defer directoryStore.Close()
		scimHandler, err = scim.New(directoryStore, secret)
		if err != nil {
			return err
		}
		users = directoryStore
	default:
		return fmt.Errorf("unknown directory-source %q", c.DirectorySource)
	}
	var managed *inventory.Managed
	if c.InventorySource == "managed" {
		stateDir, err := serviceStatePath(c.StateDir, "inventory")
		if err != nil {
			return err
		}
		managed, err = inventory.OpenManaged(stateDir, inv)
		if err != nil {
			return err
		}
		defer managed.Close()
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
	resolver := &inventoryserver.Resolver{Directory: users, Hosts: inv}
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
	if managed != nil {
		resolver.Hosts = managed
	}
	if managed != nil || directoryStore != nil {
		control := &inventoryserver.Control{Store: managed, ManagedDirectory: directoryStore, Directory: users, Validator: validator, Admins: inventoryserver.Admins{Users: c.AdminUsers, Groups: c.AdminGroups}}
		mux := http.NewServeMux()
		mux.Handle("/manage", control)
		if scimHandler != nil {
			mux.Handle("/scim/v2/", scimHandler)
		}
		mux.Handle("/", handler)
		handler = mux
	}
	logger.Info("starting inventory server", "listen", c.Listen, "files", len(paths), "directorySource", c.DirectorySource, "inventoryRevision", inv.InventoryRevision())
	return listenAndServe(c.Listen, handler)
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
