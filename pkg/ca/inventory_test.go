package ca_test

import (
	"encoding/json"
	"fmt"
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
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCAConstructsCertificateFromFactsAndPolicyLimits(t *testing.T) {
	idp := oidctest.New(t)
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	expiry := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	deadline := expiry.Add(-5 * time.Minute)
	for _, mode := range []string{"account-name", "epithet-principal-v1"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			domain := ""
			expected := "ubuntu"
			if mode == "epithet-principal-v1" {
				domain = "    domain: production\n"
				expected, err = principal.DeriveV1("production", "ubuntu")
				require.NoError(t, err)
			}
			require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("domains: [production]\nusers:\n  - id: subject:alice\n    userName: Alice\nhosts:\n  - name: host\n    accounts: [ubuntu]\n    principal-mode: %s\n%s", mode, domain)), 0600))
			inv, err := inventory.NewStatic([]string{path})
			require.NoError(t, err)
			is := inventorytest.Serve(t, inv, idp.Issuer(), pub)
			for _, tc := range []struct {
				name        string
				ttl         time.Duration
				notAfter    time.Time
				wantCeiling time.Time
				invalid     bool
			}{
				{name: "TTL from signing", ttl: time.Minute, wantCeiling: expiry},
				{name: "authentication ceiling without policy deadline", ttl: time.Hour, wantCeiling: expiry},
				{name: "tighter policy deadline", ttl: time.Hour, notAfter: deadline, wantCeiling: deadline},
				{name: "TTL tighter than both deadlines", ttl: time.Minute, notAfter: deadline, wantCeiling: deadline},
				{name: "policy cannot extend authentication", ttl: time.Hour, notAfter: expiry.Add(time.Hour), wantCeiling: expiry},
				{name: "zero TTL", invalid: true},
				{name: "negative TTL", ttl: -time.Minute, invalid: true},
				{name: "expired policy deadline", ttl: time.Hour, notAfter: time.Now().Add(-time.Minute), invalid: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ps := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						var request wire.PolicyRequest
						assert.Equal(t, "POST", r.Method)
						data, err := io.ReadAll(r.Body)
						if !assert.NoError(t, err) {
							return
						}
						assert.NotContains(t, string(data), `"token"`)
						assert.NotContains(t, string(data), `"issuer"`)
						if !assert.NoError(t, json.Unmarshal(data, &request)) {
							return
						}
						assert.Equal(t, expiry, request.Facts.Authentication.ExpiresAt)
						assert.Equal(t, "subject:alice", request.Facts.User.ID)
						// Inventory transport, principal construction, and audit metadata stay at CA.
						for _, field := range []string{"version", "resolvedAt", "revision", "directoryRevision", "inventoryRevision", "principal", "domain"} {
							assert.NotContains(t, string(data), `"`+field+`"`)
						}
						assert.Equal(t, "host", request.Facts.Target)
						if mode == "epithet-principal-v1" {
							assert.Equal(t, "production", request.Facts.Host.Name)
						} else {
							assert.Equal(t, "host", request.Facts.Host.Name)
						}
						response := wire.PolicyResponse{PolicyID: "sha256:policy", TTL: tc.ttl, NotAfter: tc.notAfter, Extensions: map[string]string{"permit-pty": ""}}
						json.NewEncoder(w).Encode(response)
					}))
					defer ps.Close()
					authority, err := ca.New(priv, ps.URL, ca.WithInventory(is.URL, tlsconfig.Config{Insecure: true}))
					require.NoError(t, err)
					result, err := authority.RequestPolicy(t.Context(), idp.MintIDToken("alice", expiry), policy.Connection{RemoteHost: "HOST", RemoteUser: "ubuntu"})
					if tc.invalid {
						require.Error(t, err)
						require.Nil(t, result)
						return
					}
					require.NoError(t, err)
					require.Equal(t, tc.wantCeiling, result.CertParams.NotAfter)
					require.Equal(t, "subject:alice", result.ID)
					require.Equal(t, "sha256:policy", result.PolicyID)
					require.Equal(t, inv.DirectoryRevision(), result.DirectoryRevision)
					require.Equal(t, inv.InventoryRevision(), result.InventoryRevision)
					if tc.name == "TTL from signing" {
						// Waiting after approval must consume absolute deadlines, not the TTL.
						time.Sleep(1100 * time.Millisecond)
					}
					before := time.Now()
					cert := signTestCert(t, authority, &result.CertParams)
					after := time.Now()
					require.Equal(t, "Alice", cert.KeyId)
					require.Equal(t, []string{expected}, cert.ValidPrincipals)
					require.Equal(t, map[string]string{"permit-pty": ""}, cert.Extensions)
					earliest, latest := before.Add(tc.ttl), after.Add(tc.ttl)
					if tc.wantCeiling.Before(earliest) {
						earliest = tc.wantCeiling
					}
					if tc.wantCeiling.Before(latest) {
						latest = tc.wantCeiling
					}
					require.GreaterOrEqual(t, cert.ValidBefore, uint64(earliest.Unix()))
					require.LessOrEqual(t, cert.ValidBefore, uint64(latest.Unix()))
				})
			}
		})
	}
}

func TestCARejectsGrantsOutsideInventoryRestrictions(t *testing.T) {
	idp := oidctest.New(t)
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	for _, tc := range []struct {
		name, user, host, account string
		allowed                   bool
	}{
		{"ungrounded accounts", "    active: true\n", "    accounts: null\n", "ubuntu", true},
		{"empty accounts", "    active: true\n", "    accounts: []\n", "ubuntu", false},
		{"different account", "    active: true\n", "    accounts: [root]\n", "ubuntu", false},
		{"empty account", "    active: true\n", "    accounts: null\n", "", false},
		{"inactive user", "    active: false\n", "    accounts: [ubuntu]\n", "ubuntu", false},
		{"missing user", "missing", "    accounts: [ubuntu]\n", "ubuntu", false},
		{"missing host", "    active: true\n", "missing", "ubuntu", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			src := ""
			if tc.user != "missing" {
				src += "users:\n  - id: subject:alice\n    userName: Alice\n" + tc.user
			}
			if tc.host != "missing" {
				src += "hosts:\n  - name: host\n" + tc.host
			}
			require.NoError(t, os.WriteFile(path, []byte(src), 0600))
			inv, err := inventory.NewStatic([]string{path})
			require.NoError(t, err)
			is := inventorytest.Serve(t, inv, idp.Issuer(), pub)
			ps := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(wire.PolicyResponse{TTL: time.Minute})
			}))
			defer ps.Close()
			authority, err := ca.New(priv, ps.URL, ca.WithInventory(is.URL, tlsconfig.Config{Insecure: true}))
			require.NoError(t, err)
			result, err := authority.RequestPolicy(t.Context(), idp.MintIDToken("alice", time.Now().Add(time.Hour)), policy.Connection{RemoteHost: "host", RemoteUser: tc.account})
			if tc.allowed {
				require.NoError(t, err)
				require.NotNil(t, result)
			} else {
				require.Error(t, err)
				require.Nil(t, result)
			}
		})
	}
}
