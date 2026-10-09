package ca_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/inventorytest"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policyserver/writpolicy"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Principal realms select certificate principals; only host names and labels
// determine which Writ resources match a connection request.
func TestIssuanceMatchesHostNamesIndependentlyOfPrincipalRealm(t *testing.T) {
	const generated = "epithet-host-id-v1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	cases := []struct {
		name, realm, policy string
		issue               bool
	}{
		{"named_realm_honors_exact_hostname_deny", "fleet", "allow * -> root@*\ndeny * -> root@prod.example.com\n", false},
		{"generated_realm_honors_exact_hostname_deny", generated, "allow * -> root@*\ndeny * -> root@prod.example.com\n", false},
		{"named_realm_honors_hostname_glob_deny", "fleet", "allow * -> root@*\ndeny * -> root@*.example.com\n", false},
		{"named_realm_accepts_exact_hostname_allow", "fleet", "allow * -> root@prod.example.com\n", true},
		{"generated_realm_accepts_exact_hostname_allow", generated, "allow * -> root@prod.example.com\n", true},
		{"named_realm_does_not_match_unrelated_hostname_allow", "dev.example.com", "allow * -> root@dev.example.com\n", false},
		{"named_realm_honors_label_deny", "fleet", "allow * -> root@*\ndeny * -> root@{env=prod}\n", false},
		{"named_realm_does_not_match_realm_named_deny", "fleet", "allow * -> root@*\ndeny * -> root@fleet\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t)
			caPub, caPriv, err := sshcert.GenerateKeys()
			require.NoError(t, err)
			userPub, _, err := sshcert.GenerateKeys()
			require.NoError(t, err)
			declared := ""
			if tc.realm != generated {
				declared = fmt.Sprintf("realms: [%s]\n", tc.realm)
			}
			// Exactly one host: a human-readable realm does not imply actual sharing.
			yaml := declared + fmt.Sprintf("users:\n - userName: alice\n   id: subject:alice\nhosts:\n - names: [prod.example.com]\n   principal-mode: epithet-principal-v1\n   realm: %s\n   labels: {env: prod}\n   accounts: [root]\n", tc.realm)
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			require.NoError(t, os.WriteFile(path, []byte(yaml), 0600))
			inv, err := inventory.NewStatic([]string{path})
			require.NoError(t, err)
			pol, diags := writ.Load(tc.policy)
			require.NotNil(t, pol, "%v", diags)
			evaluator, _, err := writpolicy.New(pol, nil, writpolicy.Options{})
			require.NoError(t, err)

			is := inventorytest.ServeFacts(t, inv, idp.Issuer(), caPub)
			authority, err := ca.New(caPriv, evaluator, is.CAOption())
			require.NoError(t, err)
			issued, err := authority.Issue(t.Context(), idp.MintIDToken("alice", time.Now().Add(time.Minute)), wire.Connection{RemoteHost: "prod.example.com", RemoteUser: "root", Port: 22}, userPub)
			if !tc.issue {
				require.ErrorIs(t, err, ca.ErrAccessDenied)
				require.Nil(t, issued)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, issued)
			cert, err := sshcert.Parse(issued.Certificate)
			require.NoError(t, err)
			expected, err := principal.DeriveV1(principal.Realm(tc.realm), "root")
			require.NoError(t, err)
			require.Equal(t, []string{expected}, cert.ValidPrincipals)
			signer, err := ssh.ParsePrivateKey([]byte(caPriv))
			require.NoError(t, err)
			require.Equal(t, signer.PublicKey().Marshal(), cert.SignatureKey.Marshal())
			checker := ssh.CertChecker{}
			require.NoError(t, checker.CheckCert(expected, cert))
		})
	}
}
