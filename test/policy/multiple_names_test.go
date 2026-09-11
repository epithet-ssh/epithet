package policy_test

import (
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
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/writpolicy"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/stretchr/testify/require"
)

func TestMultipleDNSNamesAuthorizeTheSameHost(t *testing.T) {
	const domain = "epithet-host-id-v1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	for _, mode := range []string{"account-name", "epithet-principal-v1"} {
		t.Run(mode, func(t *testing.T) {
			idp := oidctest.New(t)
			pub, priv, err := sshcert.GenerateKeys()
			require.NoError(t, err)
			config := "users:\n  - id: subject:alice\n    userName: alice\nhosts:\n  - names: [freki.home, freki.tailca597.ts.net]\n    accounts: [root]\n    principal-mode: " + mode + "\n"
			expectedPrincipal := "root"
			if mode == "epithet-principal-v1" {
				config += "    domain: " + domain + "\n"
				expectedPrincipal, err = principal.DeriveV1(principal.Domain(domain), "root")
				require.NoError(t, err)
			}
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			require.NoError(t, os.WriteFile(path, []byte(config), 0600))
			inv, err := inventory.NewStatic([]string{path})
			require.NoError(t, err)
			is := inventorytest.Serve(t, inv, idp.Issuer(), pub)
			for _, deny := range []bool{false, true} {
				src := "allow * -> root@freki.home\n"
				if deny {
					src += "deny * -> root@freki.tailca597.ts.net\n"
				}
				pol, diags := writ.Load(src)
				require.NotNil(t, pol, "%v", diags)
				e, _, err := writpolicy.New(pol, nil, writpolicy.Options{})
				require.NoError(t, err)
				h, err := policyserver.NewHandler(policyserver.Config{CAPublicKey: pub, Evaluator: e})
				require.NoError(t, err)
				ps := httptest.NewServer(h)
				t.Cleanup(ps.Close)
				authority, err := ca.New(priv, ps.URL, ca.WithInventory(is.URL, tlsconfig.Config{Insecure: true}))
				require.NoError(t, err)
				for _, target := range []string{"Freki.HOME", "freki.tailca597.ts.net"} {
					auth, err := authority.RequestPolicy(t.Context(), idp.MintIDToken("alice", time.Now().Add(time.Hour)), policy.Connection{RemoteHost: target, RemoteUser: "root"})
					if deny {
						require.ErrorIs(t, err, ca.ErrAccessDenied)
						require.Nil(t, auth)
						continue
					}
					require.NoError(t, err)
					userKey, _, err := sshcert.GenerateKeys()
					require.NoError(t, err)
					rawCert, err := authority.SignPublicKey(userKey, &auth.CertParams)
					require.NoError(t, err)
					cert, err := sshcert.Parse(rawCert)
					require.NoError(t, err)
					require.Equal(t, "alice", cert.KeyId)
					require.Equal(t, []string{expectedPrincipal}, cert.ValidPrincipals)
				}
			}
		})
	}
}
