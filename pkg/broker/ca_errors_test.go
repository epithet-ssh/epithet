package broker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/inventorytest"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

// Exercise private service statuses through CA, caclient and broker. Only user
// authentication rejection refreshes credentials; pending remains retryable by
// a later explicit match without automatically retrying or trying another CA.
func TestCAErrorsControlRefreshAndFailover(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		inventoryStatus, policyStatus        int
		refreshes, primaryCalls, backupCalls int32
		pending                              bool
	}{
		{name: "policy service credential", policyStatus: 401, primaryCalls: 1, backupCalls: 1},
		{name: "inventory service credential", inventoryStatus: 403, primaryCalls: 1, backupCalls: 1},
		{name: "user authentication", inventoryStatus: 401, primaryCalls: 2, refreshes: 1},
		{name: "denied", policyStatus: 403, primaryCalls: 1},
		{name: "pending", policyStatus: 202, primaryCalls: 1, pending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t)
			pub, priv, err := sshcert.GenerateKeys()
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			require.NoError(t, os.WriteFile(path, []byte("users:\n  - id: subject:user\n    userName: user\nhosts:\n  - names: [host]\n"), 0600))
			inv, err := inventory.NewStatic([]string{path})
			require.NoError(t, err)
			realInventory := inventorytest.Serve(t, inv, idp.Issuer(), pub)
			inventoryHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.inventoryStatus != 0 {
					w.WriteHeader(tc.inventoryStatus)
					fmt.Fprint(w, "private inventory diagnostic")
					return
				}
				realInventory.Config.Handler.ServeHTTP(w, r)
			}))
			defer inventoryHTTP.Close()
			policyHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.policyStatus)
				fmt.Fprint(w, "private policy diagnostic")
			}))
			defer policyHTTP.Close()
			c, err := ca.New(priv, policyHTTP.URL, ca.WithInventory(inventoryHTTP.URL, tlsconfig.Config{Insecure: true}))
			require.NoError(t, err)
			logger := slog.New(slog.DiscardHandler)
			handler := caserver.New(c, logger, nil).Handler()
			var primaryCalls, backupCalls atomic.Int32
			primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				primaryCalls.Add(1)
				handler.ServeHTTP(w, r)
			}))
			defer primary.Close()
			backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backupCalls.Add(1)
				http.Error(w, "invalid certificate request", http.StatusBadRequest)
			}))
			defer backup.Close()
			client, err := caclient.New([]caclient.CAEndpoint{{URL: primary.URL, Priority: 200}, {URL: backup.URL, Priority: 100}})
			require.NoError(t, err)
			var refreshes atomic.Int32
			token := idp.MintIDToken("user", time.Now().Add(time.Hour))
			tokenFn := func(_ context.Context, _ io.Writer, force bool) (string, error) {
				if force {
					refreshes.Add(1)
				}
				return token, nil
			}
			dir := shortTempDir(t)
			b, err := New(*logger, dir+"/b.sock", tokenFn, client, dir+"/agents")
			require.NoError(t, err)
			b.SetShutdownTimeout(0)
			t.Cleanup(b.Close)
			conn := policy.Connection{RemoteHost: "host", RemoteUser: "root", Hash: "connection"}
			result := b.MatchWithUserOutput(t.Context(), conn, io.Discard)
			require.False(t, result.Allow)
			require.NotContains(t, result.Error, "private")
			require.Equal(t, tc.refreshes, refreshes.Load())
			require.Equal(t, tc.primaryCalls, primaryCalls.Load())
			require.Equal(t, tc.backupCalls, backupCalls.Load())
			require.Empty(t, b.agents)
			if tc.pending {
				require.Contains(t, result.Error, "authorization pending; try again later")
				result = b.MatchWithUserOutput(t.Context(), conn, io.Discard)
				require.False(t, result.Allow)
				require.Contains(t, result.Error, "authorization pending; try again later")
				require.Equal(t, int32(2), primaryCalls.Load(), "a later match tries the same CA again")
				require.Zero(t, backupCalls.Load())
				require.Zero(t, refreshes.Load())
			}
		})
	}
}
