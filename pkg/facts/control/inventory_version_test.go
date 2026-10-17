package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

// A fixed record and captured arguments exercise the protocol without another
// storage implementation. Unused methods on the embedded interfaces panic.
type inventoryVersionFixture struct {
	inventory.Store
	inventory.Hosts
	record          inventory.Host
	expectedVersion string
	removed         bool
}

func (f *inventoryVersionFixture) SupportsVersioning() bool { return f.record.Version != "" }
func (f *inventoryVersionFixture) GetHost(context.Context, string) (*inventory.Host, error) {
	copy := f.record
	return &copy, nil
}
func (f *inventoryVersionFixture) UpsertHost(_ context.Context, h inventory.Host, conditions inventory.WriteConditions, _ inventory.AuditEvent) (*inventory.Host, error) {
	f.expectedVersion = conditions.ExpectedVersion
	if f.SupportsVersioning() {
		h.Version = "next:opaque/version"
	}
	return &h, nil
}
func (f *inventoryVersionFixture) RemoveHost(_ context.Context, _ string, expectedVersion string, _ inventory.AuditEvent) error {
	f.expectedVersion, f.removed = expectedVersion, true
	return nil
}

func TestInventoryOptionalOpaqueVersions(t *testing.T) {
	for _, version := range []string{"", "backend:opaque/9+hash=="} {
		t.Run(version, func(t *testing.T) {
			public, key, err := sshcert.GenerateKeys()
			require.NoError(t, err)
			now := time.Now().UTC()
			fixture := &inventoryVersionFixture{record: inventory.Host{ID: inventory.NewID(), Version: version, Status: inventory.StatusPending, Names: []string{"host.example"}, PrincipalMode: inventory.AccountNamePrincipals, CreatedAt: now, UpdatedAt: now}}
			handler, err := factserver.InventoryHandler(fixture, "", public, factserver.WithInventoryManagement(fixture))
			require.NoError(t, err)
			var match string
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PUT" || r.Method == "DELETE" {
					match = r.Header.Get("If-Match")
				}
				handler.ServeHTTP(w, r)
			}))
			defer provider.Close()
			client, err := newProviderTestServer("", provider.URL+"/lookup", key, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			auth := authorization{Actor: "admin"}
			h, err := client.host(t.Context(), auth, fixture.record.ID)
			require.NoError(t, err)
			require.Equal(t, version, h.Version)
			approved, err := client.approveHost(t.Context(), auth, h.ID, h.Version)
			require.NoError(t, err)
			require.Equal(t, inventory.StatusActive, approved.Status)
			require.Equal(t, version, fixture.expectedVersion)
			if version == "" {
				require.Empty(t, match)
				require.Empty(t, approved.Version)
			} else {
				require.Equal(t, `"`+version+`"`, match)
				require.Equal(t, "next:opaque/version", approved.Version)
			}
			// A precondition is required only for versioned providers;
			// an unversioned provider cannot honor an explicit version match.
			badVersion, wantStatus := "", http.StatusPreconditionRequired
			if version == "" {
				badVersion, wantStatus = "asserted-version", http.StatusPreconditionFailed
			}
			err = client.removeHost(t.Context(), auth, h.ID, badVersion)
			var rejected *facts.ServiceError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, wantStatus, rejected.Status)
			require.False(t, fixture.removed)
			require.NoError(t, client.removeHost(t.Context(), auth, h.ID, h.Version))
			require.True(t, fixture.removed)
			require.Equal(t, version, fixture.expectedVersion)
			if version == "" {
				require.Empty(t, match)
			}
		})
	}
}
