// Package controltest runs the real public control service and private backends.
package controltest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/controlplane"
	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/factservice"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

type Fixture struct {
	*httptest.Server
	Control                    *controlplane.Server
	DirectoryURL, InventoryURL string
	CAKey, ControlKey          sshcert.RawPrivateKey
}
type emptyDirectory struct{}

func (emptyDirectory) LookupUser(context.Context, string) (*directory.User, directory.Revision, error) {
	return nil, "", nil
}

type noAuthentication struct{}

func (noAuthentication) Validate(context.Context, string) (*oidc.Claims, error) {
	return nil, fmt.Errorf("no authentication configured")
}

func New(t *testing.T, users directory.Directory, managed directory.Store, hosts *inventory.Managed, config controlplane.Config) *Fixture {
	t.Helper()
	caPub, caKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	f := &Fixture{CAKey: caKey, ControlKey: key}
	if users == nil {
		users = emptyDirectory{}
	}
	facts, err := factservice.Handler(users, nil, caPub, pub)
	require.NoError(t, err)
	backend, err := (&controlplane.Backend{Directory: users, ManagedDirectory: managed}).Handler(pub)
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.Handle("/lookup", facts)
	mux.Handle("/", backend)
	ds := httptest.NewServer(mux)
	t.Cleanup(ds.Close)
	f.DirectoryURL = ds.URL
	config.Key = key
	config.DirectoryURL = ds.URL
	config.DirectoryBackendURL = ds.URL
	config.TLS = tlsconfig.Config{Insecure: true}
	if hosts != nil {
		h, err := (&controlplane.Backend{Store: hosts}).Handler(pub)
		require.NoError(t, err)
		is := httptest.NewServer(h)
		t.Cleanup(is.Close)
		f.InventoryURL = is.URL
		config.InventoryBackendURL = is.URL
	}
	if config.Validator == nil {
		config.Validator = noAuthentication{}
	}
	f.Control, err = controlplane.New(config)
	require.NoError(t, err)
	f.Server = httptest.NewServer(f.Control)
	t.Cleanup(f.Close)
	return f
}
