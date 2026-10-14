package inventorytest

import (
	"context"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func writeInv(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

const basicInventory = `
users:
  - userName: alice@example.com
    id: subject:alice@example.com
    groups: [{name: [SRE]}, {name: [Engineering]}]
    userType: employee
    department: Platform
    organization: Acme
  - userName: mallory@example.com
    id: subject:mallory@example.com
    active: false
    groups: [{name: [SRE]}]

hosts:
  - names: [PROD-DB-1]
    labels: {env: prod, role: db}
    accounts: [root, postgres]
  - names: [dev-box]
    labels: {env: dev}
  - pattern: "ci-runner-*"
    labels: {env: ci, ephemeral: "true"}
`

const inventoryGeneratedRealm = "epithet-host-id-v1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func TestStaticLookupIncludingMissingHosts(t *testing.T) {
	s, err := NewStatic([]string{writeInv(t, "inventory.yaml", basicInventory)})
	require.NoError(t, err)
	for _, name := range []string{"prod-db-1", "ci-runner-42", "missing"} {
		t.Run(name, func(t *testing.T) {
			host, err := s.LookupHost(t.Context(), name)
			require.NoError(t, err)
			if name == "missing" {
				require.Nil(t, host)
			} else {
				require.NotNil(t, host)
			}
		})
	}
}

func TestMultipleNamesResolveOneHost(t *testing.T) {
	for _, realm := range []string{inventoryGeneratedRealm, "fleet"} {
		t.Run(realm, func(t *testing.T) {
			src := "realms: [fleet]\nhosts:\n  - names: [Freki.HOME, freki.tailca597.ts.net]\n    principal-mode: epithet-principal-v1\n    realm: " + realm + "\n    labels: {role: server}\n    accounts: [brianm]\n  - pattern: '**'\n    accounts: []\n"
			s, err := NewStatic([]string{writeInv(t, "names.yaml", src)})
			require.NoError(t, err)
			var first *inventory.Host
			for _, name := range []string{"freki.home", "freki.tailca597.ts.net"} {
				host, err := s.LookupHost(t.Context(), name)
				require.NoError(t, err)
				require.NotNil(t, host)
				require.Equal(t, []string{"freki.home", "freki.tailca597.ts.net"}, host.Names)
				require.Equal(t, realm, host.Realm.String())
				require.Equal(t, []string{"brianm"}, host.Accounts)
				require.Equal(t, "server", host.Labels["role"])
				if first == nil {
					first = host
				} else {
					require.Same(t, first, host)
				}
			}
		})
	}
}

func TestInvalidHostNames(t *testing.T) {
	for _, tc := range []struct{ name, src, error string }{
		{"empty", "  - names: []\n", "names must not be empty"},
		{"empty member", "  - names: [host, '']\n", "empty DNS name"},
		{"repeated", "  - names: [host, HOST]\n", "duplicate host name"},
		{"overlap", "  - names: [host, alias]\n  - names: [ALIAS]\n", "duplicate host name"},
		{"singular field", "  - name: host\n", "field name not found"},
		{"singular with names", "  - name: host\n    names: [alias]\n", "field name not found"},
		{"pattern", "  - names: [host]\n    pattern: '*'\n", "both names and pattern"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewStatic([]string{writeInv(t, "names.yaml", "hosts:\n"+tc.src)})
			require.ErrorContains(t, err, tc.error)
		})
	}
	_, err := NewStatic([]string{
		writeInv(t, "one.yaml", "hosts:\n  - names: [host, alias]\n"),
		writeInv(t, "two.yaml", "hosts:\n  - names: [ALIAS, other]\n"),
	})
	require.ErrorContains(t, err, "duplicate host name")
}

func loadBasic(t *testing.T) *Static {
	t.Helper()
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", basicInventory)})
	require.NoError(t, err)
	return s
}

func TestLookupUser(t *testing.T) {
	s := loadBasic(t)
	u, err := s.LookupUser(context.Background(), "subject:alice@example.com")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, "alice@example.com", u.UserName)
	require.Equal(t, "subject:alice@example.com", u.ID)
	require.True(t, u.Active, "active defaults to true")
	require.Equal(t, []string{"Engineering", "SRE"}, object.GroupNames(u.Facts().Groups))
	require.Equal(t, "employee", u.UserType)
	require.Equal(t, "Platform", u.Department)
	require.Equal(t, "Acme", u.Organization)
}

func TestInactiveUserLoads(t *testing.T) {
	s := loadBasic(t)
	u, err := s.LookupUser(context.Background(), "subject:mallory@example.com")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.False(t, u.Active)
}

func TestUnknownUserIsNilNil(t *testing.T) {
	s := loadBasic(t)
	u, err := s.LookupUser(context.Background(), "nobody@example.com")
	require.NoError(t, err)
	require.Nil(t, u)
}

func TestLookupUserNeverFallsBackToUserName(t *testing.T) {
	s := loadBasic(t)
	for _, subject := range []string{"alice@example.com", "Subject:alice@example.com", ""} {
		u, err := s.LookupUser(context.Background(), subject)
		require.NoError(t, err)
		require.Nil(t, u, "ID must match exactly, without fallback: %q", subject)
	}
}

func TestUserRequiresID(t *testing.T) {
	for _, field := range []string{"", "    id: ''\n", "    id: null\n"} {
		_, err := NewStatic([]string{writeInv(t, "inv.yaml", "users:\n  - userName: alice@example.com\n"+field)})
		require.ErrorContains(t, err, "has no id")
	}
}

func TestDuplicateIDAcrossFilesIsError(t *testing.T) {
	one := "users:\n  - userName: alice\n    id: '12345'\n"
	two := "users:\n  - userName: bob\n    id: '12345'\n"
	_, err := NewStatic([]string{writeInv(t, "a.yaml", one), writeInv(t, "b.yaml", two)})
	require.ErrorContains(t, err, "duplicate id")
}

func TestExactHostLowercasedAtLoad(t *testing.T) {
	s := loadBasic(t)
	h, err := s.LookupHost(context.Background(), "prod-db-1")
	require.NoError(t, err)
	require.NotNil(t, h)
	require.Equal(t, []string{"prod-db-1"}, h.Names)
	require.Equal(t, map[string]string{"env": "prod", "role": "db"}, h.Labels)
	require.Equal(t, []string{"root", "postgres"}, h.Accounts)
}

func TestHostWithoutAccountsIsUngrounded(t *testing.T) {
	s := loadBasic(t)
	h, err := s.LookupHost(context.Background(), "dev-box")
	require.NoError(t, err)
	require.NotNil(t, h)
	require.Nil(t, h.Accounts)
}

func TestPatternSynthesizesHost(t *testing.T) {
	s := loadBasic(t)
	h, err := s.LookupHost(context.Background(), "ci-runner-42")
	require.NoError(t, err)
	require.NotNil(t, h)
	require.Equal(t, []string{"ci-runner-42"}, h.Names, "synthesized host adopts the requested name")
	require.Equal(t, "ci", h.Labels["env"])
	require.Nil(t, h.Accounts)
}

func TestPatternStarStopsAtLabelBoundary(t *testing.T) {
	s := loadBasic(t)
	h, err := s.LookupHost(context.Background(), "ci-runner-42.internal")
	require.NoError(t, err)
	require.Nil(t, h)
}

func TestPatternDoublestarCrossesLabelBoundaries(t *testing.T) {
	src := "hosts:\n  - pattern: '**.controlplane.internal'\n"
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)

	for _, name := range []string{"controlplane.internal", "api.controlplane.internal", "blue.api.controlplane.internal"} {
		h, err := s.LookupHost(context.Background(), name)
		require.NoError(t, err)
		require.NotNil(t, h, name)
	}
}

func TestInvalidPatternSyntaxIsLoadError(t *testing.T) {
	patterns := []string{
		"host{,.internal}",
		"host[0-9].internal",
		`host\*.internal`,
		"host/internal",
		"host**.internal",
		"host.***.internal",
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			src := "hosts:\n  - pattern: '" + pattern + "'\n"
			_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
			require.ErrorContains(t, err, "hosts[0] pattern")
		})
	}
}

func TestHashedDefaultRequiresAndLoadsExactRealm(t *testing.T) {
	src := "hosts:\n  - names: [prod-1]\n    realm: " + inventoryGeneratedRealm + "\n"
	s, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(inventory.EpithetPrincipalV1))
	require.NoError(t, err)

	h, err := s.LookupHost(context.Background(), "prod-1")
	require.NoError(t, err)
	require.Equal(t, inventory.EpithetPrincipalV1, h.PrincipalMode)
	require.Equal(t, inventoryGeneratedRealm, h.Realm.String())
}

func TestPatternCanFallBackFromHashedDefault(t *testing.T) {
	src := `
hosts:
  - pattern: "ci-*"
    principal-mode: account-name
    accounts: [ubuntu]
`
	s, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(inventory.EpithetPrincipalV1))
	require.NoError(t, err)

	h, err := s.LookupHost(context.Background(), "ci-42")
	require.NoError(t, err)
	require.Equal(t, inventory.AccountNamePrincipals, h.PrincipalMode)
	require.Equal(t, []string{"ubuntu"}, h.Accounts)
	require.Empty(t, h.Realm)
}

func TestExactHostCanFallBackFromHashedDefault(t *testing.T) {
	src := `
hosts:
  - names: [legacy-1]
    principal-mode: account-name
`
	s, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(inventory.EpithetPrincipalV1))
	require.NoError(t, err)

	h, err := s.LookupHost(context.Background(), "legacy-1")
	require.NoError(t, err)
	require.Equal(t, inventory.AccountNamePrincipals, h.PrincipalMode)
}

func TestHashedExactHostWithoutRealmIsError(t *testing.T) {
	src := "hosts:\n  - names: [prod-1]\n"
	_, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(inventory.EpithetPrincipalV1))
	require.ErrorContains(t, err, "has no realm")
}

func TestHashedPatternLoadsDeclaredNamedRealm(t *testing.T) {
	src := "realms: [production]\nhosts:\n  - pattern: 'prod-*'\n    realm: production\n"
	s, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(inventory.EpithetPrincipalV1))
	require.NoError(t, err)

	host, err := s.LookupHost(context.Background(), "prod-worker-1")
	require.NoError(t, err)
	require.Equal(t, inventory.EpithetPrincipalV1, host.PrincipalMode)
	require.Equal(t, "production", host.Realm.String())
	require.Equal(t, []string{"prod-worker-1"}, host.Names)
}

func TestPatternWithGeneratedHostRealm(t *testing.T) {
	src := "hosts:\n  - pattern: 'prod-*'\n    principal-mode: account-name\n    realm: " + inventoryGeneratedRealm + "\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
}

func TestMalformedRealmIsError(t *testing.T) {
	src := "hosts:\n  - names: [prod-1]\n    realm: 'not a realm'\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "realm")
}

func TestUndeclaredNamedRealmIsError(t *testing.T) {
	src := "hosts:\n  - pattern: 'prod-*'\n    principal-mode: epithet-principal-v1\n    realm: prodution\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, `references undeclared realm "prodution"`)
}

func TestNamedRealmMayBeDeclaredInLaterFile(t *testing.T) {
	hosts := "hosts:\n  - pattern: 'prod-*'\n    principal-mode: epithet-principal-v1\n    realm: production\n"
	realms := "realms: [production]\n"
	_, err := NewStatic([]string{writeInv(t, "hosts.yaml", hosts), writeInv(t, "realms.yaml", realms)})
	require.NoError(t, err)
}

func TestDuplicateNamedRealmIsError(t *testing.T) {
	one := "realms: [production]\n"
	_, err := NewStatic([]string{writeInv(t, "a.yaml", one), writeInv(t, "b.yaml", one)})
	require.ErrorContains(t, err, `duplicate realm "production"`)
}

func TestNamedRealmRequiresHashedPrincipalMode(t *testing.T) {
	src := "realms: [production]\nhosts:\n  - pattern: 'prod-*'\n    realm: production\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "named realm")
	require.ErrorContains(t, err, string(inventory.EpithetPrincipalV1))
}

func TestNamedRealmEntriesMayHaveDifferentAuthorizationAttributes(t *testing.T) {
	src := `
realms: [production]
hosts:
  - names: [prod-1]
    realm: production
    principal-mode: epithet-principal-v1
    labels: {role: web}
  - names: [prod-2]
    realm: production
    principal-mode: epithet-principal-v1
    labels: {role: database}
`
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
}

func TestNamedRealmEntriesPreserveHostNames(t *testing.T) {
	src := `
realms: [production]
hosts:
  - names: [prod-1]
    realm: production
    principal-mode: epithet-principal-v1
    labels: {env: prod}
  - names: [prod-2]
    realm: production
    principal-mode: epithet-principal-v1
    labels: {env: prod}
`
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)

	one, err := s.LookupHost(context.Background(), "prod-1")
	require.NoError(t, err)
	two, err := s.LookupHost(context.Background(), "prod-2")
	require.NoError(t, err)
	require.Equal(t, []string{"prod-1"}, one.Names)
	require.Equal(t, []string{"prod-2"}, two.Names)
	require.Equal(t, one.Labels, two.Labels)
	require.Equal(t, one.Accounts, two.Accounts)
	require.Equal(t, one.Realm, two.Realm)
}

func TestNamedRealmAccountOrderDoesNotChangeAuthorizationAttributes(t *testing.T) {
	src := `
realms: [production]
hosts:
  - names: [prod-1]
    realm: production
    principal-mode: epithet-principal-v1
    accounts: [root, ubuntu]
  - names: [prod-2]
    realm: production
    principal-mode: epithet-principal-v1
    accounts: [ubuntu, root]
`
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
}

func TestNamedRealmDistinguishesAbsentAndEmptyAccountGrounding(t *testing.T) {
	src := `
realms: [production]
hosts:
  - names: [prod-1]
    realm: production
    principal-mode: epithet-principal-v1
  - names: [prod-2]
    realm: production
    principal-mode: epithet-principal-v1
    accounts: []
`
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
}

func TestUnknownPrincipalModeIsError(t *testing.T) {
	src := "hosts:\n  - names: [prod-1]\n    principal-mode: mystery\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, `unknown principal mode "mystery"`)
}

func TestUnknownHostIsNilNil(t *testing.T) {
	s := loadBasic(t)
	h, err := s.LookupHost(context.Background(), "unknown-host")
	require.NoError(t, err)
	require.Nil(t, h)
}

func TestExactEntryWinsOverPattern(t *testing.T) {
	src := `
hosts:
  - names: [ci-runner-1]
    labels: {env: prod}
  - pattern: "ci-runner-*"
    labels: {env: ci}
`
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
	h, err := s.LookupHost(context.Background(), "ci-runner-1")
	require.NoError(t, err)
	require.Equal(t, "prod", h.Labels["env"])
}

func TestFirstMatchingPatternWins(t *testing.T) {
	src := `
hosts:
  - pattern: "ci-*"
    labels: {tier: broad}
  - pattern: "ci-runner-*"
    labels: {tier: narrow}
`
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
	h, err := s.LookupHost(context.Background(), "ci-runner-1")
	require.NoError(t, err)
	require.Equal(t, "broad", h.Labels["tier"], "pattern entries match in file order")
}

func TestEmptyAccountsListStaysNonNil(t *testing.T) {
	src := `
hosts:
  - names: [locked-down]
    accounts: []
`
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
	h, err := s.LookupHost(context.Background(), "locked-down")
	require.NoError(t, err)
	require.NotNil(t, h.Accounts, "accounts: [] grounds nothing, which is different from absent")
	require.Empty(t, h.Accounts)
}

func TestMultipleFilesConcatenate(t *testing.T) {
	users := "users:\n  - userName: alice@example.com\n    id: subject:alice@example.com\n"
	hosts := "hosts:\n  - names: [web-1]\n"
	s, err := NewStatic([]string{writeInv(t, "users.yaml", users), writeInv(t, "hosts.yaml", hosts)})
	require.NoError(t, err)
	u, _ := s.LookupUser(context.Background(), "subject:alice@example.com")
	require.NotNil(t, u)
	h, _ := s.LookupHost(context.Background(), "web-1")
	require.NotNil(t, h)
}

func TestDuplicateUserAcrossFilesIsError(t *testing.T) {
	one := "users:\n  - userName: alice@example.com\n    id: subject:alice@example.com\n"
	_, err := NewStatic([]string{writeInv(t, "a.yaml", one), writeInv(t, "b.yaml", one)})
	require.ErrorContains(t, err, "duplicate user")
}

func TestDuplicateHostIsError(t *testing.T) {
	src := "hosts:\n  - names: [web-1]\n  - names: [WEB-1]\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "duplicate host")
}

func TestUnknownFieldIsError(t *testing.T) {
	src := "users:\n  - userName: alice@example.com\n    id: subject:alice@example.com\n    grops: [SRE]\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "grops")
}

func TestUsersWithoutUserNames(t *testing.T) {
	path := writeInv(t, "inv.yaml", "users:\n - id: first\n - id: second\n")
	inv, err := NewStatic([]string{path})
	require.NoError(t, err)
	for _, id := range []string{"first", "second"} {
		user, err := inv.LookupUser(t.Context(), id)
		require.NoError(t, err)
		require.Equal(t, id, user.ID)
		require.Empty(t, user.UserName)
	}
}

func TestHostWithNamesAndPatternIsError(t *testing.T) {
	src := "hosts:\n  - names: [a]\n    pattern: \"b*\"\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "pick one")
}

func TestNoFilesIsError(t *testing.T) {
	_, err := NewStatic(nil)
	require.Error(t, err)
}

func TestEmptyFileIsEmptyInventory(t *testing.T) {
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", "")})
	require.NoError(t, err)
	u, err := s.LookupUser(context.Background(), "anyone")
	require.NoError(t, err)
	require.Nil(t, u)
}

func TestLegacySubjectKeysAreRejected(t *testing.T) {
	for _, key := range []string{"subject", "oidc-subject"} {
		for _, prefix := range []string{"", "    id: current\n"} {
			_, err := NewStatic([]string{writeInv(t, "inv.yaml", "users:\n  - userName: alice\n"+prefix+"    "+key+": legacy\n")})
			require.ErrorContains(t, err, key)
		}
	}
}
