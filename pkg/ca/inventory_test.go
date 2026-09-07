package ca_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/inventorytest"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestCAConstrainsPolicyResponseToResolvedFacts(t *testing.T) {
	idp := oidctest.New(t)
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	require.NoError(t, os.WriteFile(path, []byte("users:\n  - id: subject:alice\n    userName: Alice\nhosts:\n  - name: host\n    accounts: [ubuntu]\n"), 0600))
	inv, err := inventory.NewStatic([]string{path})
	require.NoError(t, err)
	is := inventorytest.Serve(t, inv, idp.Issuer(), pub)
	expiry := time.Now().Add(2 * time.Minute).Truncate(time.Second)
	for _, tc := range []struct {
		name   string
		change func(*wire.PolicyResponse)
		valid  bool
	}{
		{"bounded valid response", func(r *wire.PolicyResponse) {}, true},
		{"different id", func(r *wire.PolicyResponse) { r.ID = "mallory" }, false},
		{"different username", func(r *wire.PolicyResponse) { r.CertParams.Identity = "Mallory" }, false},
		{"different account", func(r *wire.PolicyResponse) { r.CertParams.Names = []string{"root"} }, false},
		{"extra principal", func(r *wire.PolicyResponse) { r.CertParams.Names = append(r.CertParams.Names, "root") }, false},
		{"nonpositive lifetime", func(r *wire.PolicyResponse) { r.CertParams.Expiration = 0 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request wire.PolicyRequest
				require.Equal(t, "POST", r.Method)
				data, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.NotContains(t, string(data), `"token"`)
				require.NotContains(t, string(data), `"issuer"`)
				require.NoError(t, json.Unmarshal(data, &request))
				require.Equal(t, expiry, request.Facts.Authentication.ExpiresAt)
				require.Equal(t, "subject:alice", request.Facts.Directory.User.ID)
				response := wire.PolicyResponse{DirectoryRevision: "invented", InventoryRevision: "invented", CertParams: wire.CertParams{Identity: "Alice", Names: []string{"ubuntu"}, Expiration: time.Hour, NotAfter: time.Now().Add(time.Hour)}}
				tc.change(&response)
				json.NewEncoder(w).Encode(response)
			}))
			defer ps.Close()
			authority, err := ca.New(priv, ps.URL, ca.WithInventory(is.URL, tlsconfig.Config{Insecure: true}))
			require.NoError(t, err)
			result, err := authority.RequestPolicy(t.Context(), idp.MintIDToken("alice", expiry), policy.Connection{RemoteHost: "HOST", RemoteUser: "ubuntu"})
			if !tc.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, expiry, result.CertParams.NotAfter)
			require.Equal(t, "subject:alice", result.ID)
			require.Equal(t, inv.DirectoryRevision(), result.DirectoryRevision)
			require.Equal(t, inv.InventoryRevision(), result.InventoryRevision)
		})
	}
}
