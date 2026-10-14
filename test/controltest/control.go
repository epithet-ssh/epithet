// Package controltest runs the real public control service and private backends.
package controltest

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/control"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

type Fixture struct {
	*httptest.Server
	Control                    *control.Server
	DirectoryURL, InventoryURL string
	CAKey, ControlKey          sshcert.RawPrivateKey
}
type emptyDirectory struct{}

func (emptyDirectory) LookupUser(context.Context, string) (*directory.User, error) {
	return nil, nil
}

type noAuthentication struct{}

func (noAuthentication) Validate(context.Context, string) (*oidc.Claims, error) {
	return nil, fmt.Errorf("no authentication configured")
}

// Most control fixtures use a single inventory instance for both planes.
type managedInventory interface {
	inventory.Hosts
	inventory.Store
}

func New(t *testing.T, users directory.Directory, managed directory.Store, hosts managedInventory, config control.Config) *Fixture {
	t.Helper()
	caPub, caKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	f := &Fixture{CAKey: caKey, ControlKey: key}
	if users == nil {
		users = emptyDirectory{}
	}
	handler, err := factserver.DirectoryHandler(users, caPub, pub, factserver.WithDirectoryManagement(managed))
	require.NoError(t, err)
	ds := httptest.NewServer(handler)
	t.Cleanup(ds.Close)
	f.DirectoryURL = ds.URL
	config.Key = key
	config.DirectoryURL = ds.URL + "/lookup"
	config.DirectoryBackendURL = ds.URL
	config.TLS = tlsconfig.Config{Insecure: true}
	if hosts != nil {
		h, err := factserver.InventoryHandler(hosts, caPub, pub, factserver.WithInventoryManagement(hosts))
		require.NoError(t, err)
		is := httptest.NewServer(h)
		t.Cleanup(is.Close)
		f.InventoryURL = is.URL + "/lookup"
		config.InventoryBackendURL = f.InventoryURL
	}
	if config.Validator == nil {
		config.Validator = noAuthentication{}
	}
	f.Control, err = control.New(config)
	require.NoError(t, err)
	f.Server = httptest.NewServer(f.Control)
	t.Cleanup(f.Close)
	return f
}
