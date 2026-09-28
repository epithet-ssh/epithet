package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/controlplane"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type ControlCLI struct {
	Listen               string            `help:"Control listener" default:"127.0.0.1:9996"`
	Key                  string            `help:"Configured control signing key" default:"/etc/epithet/control.key" name:"control-key-file"`
	Directory            string            `placeholder:"URL" help:"Directory fact service URL" required:"true" name:"directory"`
	DirectoryBackend     string            `placeholder:"URL" help:"Built-in directory administration service URL" name:"directory-backend"`
	InventoryBackend     string            `placeholder:"URL" help:"Built-in inventory administration service URL" name:"inventory-backend"`
	OIDC                 ServiceOIDCConfig `embed:"" prefix:"oidc-"`
	DirectoryAdminUsers  []string          `help:"Directory administrator user IDs" name:"directory-admin-user"`
	DirectoryAdminGroups []string          `help:"Directory administrator groups" name:"directory-admin-group"`
	InventoryAdminUsers  []string          `help:"Inventory administrator user IDs" name:"inventory-admin-user"`
	InventoryAdminGroups []string          `help:"Inventory administrator groups" name:"inventory-admin-group"`
	SCIMToken            string            `help:"SCIM provisioning bearer token" name:"scim-token"`
	SCIMTokenFile        string            `help:"SCIM provisioning bearer token file" name:"scim-token-file"`
}

func (c *ControlCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	key, err := os.ReadFile(c.Key)
	if err != nil {
		return fmt.Errorf("reading control key: %w", err)
	}
	token, err := c.provisioningToken()
	if err != nil {
		return err
	}
	validator, err := oidc.NewValidator(context.Background(), oidc.Config{Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, IdentityMode: c.OIDC.IdentityMode, UserIDClaim: c.OIDC.UserIDClaim, TLSConfig: tlsCfg})
	if err != nil {
		return err
	}
	handler, err := controlplane.New(controlplane.Config{Key: sshcert.RawPrivateKey(key), DirectoryURL: c.Directory, DirectoryBackendURL: c.DirectoryBackend, InventoryBackendURL: c.InventoryBackend, Validator: validator, DirectoryAdmins: controlplane.Admins{Users: c.DirectoryAdminUsers, Groups: c.DirectoryAdminGroups}, InventoryAdmins: controlplane.Admins{Users: c.InventoryAdminUsers, Groups: c.InventoryAdminGroups}, SCIMToken: token, TLS: tlsCfg})
	if err != nil {
		return err
	}
	logger.Info("starting control server", "listen", c.Listen)
	return listenAndServe(c.Listen, handler)
}

func (c *ControlCLI) provisioningToken() (string, error) {
	if c.SCIMToken != "" && c.SCIMTokenFile != "" {
		return "", fmt.Errorf("use either scim-token or scim-token-file")
	}
	token := c.SCIMToken
	if c.SCIMTokenFile != "" {
		path, err := expandPath(c.SCIMTokenFile)
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading SCIM token: %w", err)
		}
		token = strings.TrimSpace(string(data))
	}
	if c.SCIMTokenFile != "" && token == "" {
		return "", fmt.Errorf("SCIM token file must contain a nonempty bearer token")
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("SCIM requires a bearer token without whitespace")
	}
	return token, nil
}
