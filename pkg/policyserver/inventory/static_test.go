package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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
    groups: [SRE, Engineering]
    userType: employee
    department: Platform
    organization: Acme
  - userName: mallory@example.com
    active: false
    groups: [SRE]

hosts:
  - name: PROD-DB-1
    labels: {env: prod, role: db}
    accounts: [root, postgres]
  - name: dev-box
    labels: {env: dev}
  - pattern: "ci-runner-*"
    labels: {env: ci, ephemeral: "true"}
`

const inventoryGeneratedDomain = "epithet-host-id-v1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func loadBasic(t *testing.T) *Static {
	t.Helper()
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", basicInventory)})
	require.NoError(t, err)
	return s
}

func TestLookupUser(t *testing.T) {
	s := loadBasic(t)
	u, err := s.LookupUser(context.Background(), "alice@example.com")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, "alice@example.com", u.ID)
	require.True(t, u.Active, "active defaults to true")
	require.Equal(t, []string{"SRE", "Engineering"}, u.Groups)
	require.Equal(t, "employee", u.Type)
	require.Equal(t, "Platform", u.Dept)
	require.Equal(t, "Acme", u.Org)
}

func TestInactiveUserLoads(t *testing.T) {
	s := loadBasic(t)
	u, err := s.LookupUser(context.Background(), "mallory@example.com")
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

func TestExactHostLowercasedAtLoad(t *testing.T) {
	s := loadBasic(t)
	h, err := s.LookupHost(context.Background(), "prod-db-1")
	require.NoError(t, err)
	require.NotNil(t, h)
	require.Equal(t, "prod-db-1", h.Policy.Name)
	require.Equal(t, map[string]string{"env": "prod", "role": "db"}, h.Policy.Labels)
	require.Equal(t, []string{"root", "postgres"}, h.Policy.Accounts)
}

func TestHostWithoutAccountsIsUngrounded(t *testing.T) {
	s := loadBasic(t)
	h, err := s.LookupHost(context.Background(), "dev-box")
	require.NoError(t, err)
	require.NotNil(t, h)
	require.Nil(t, h.Policy.Accounts)
}

func TestPatternSynthesizesHost(t *testing.T) {
	s := loadBasic(t)
	h, err := s.LookupHost(context.Background(), "ci-runner-42")
	require.NoError(t, err)
	require.NotNil(t, h)
	require.Equal(t, "ci-runner-42", h.Policy.Name, "synthesized host adopts the requested name")
	require.Equal(t, "ci", h.Policy.Labels["env"])
	require.Nil(t, h.Policy.Accounts)
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

func TestHashedDefaultRequiresAndLoadsExactDomain(t *testing.T) {
	src := "hosts:\n  - name: prod-1\n    domain: " + inventoryGeneratedDomain + "\n"
	s, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(EpithetPrincipalV1))
	require.NoError(t, err)

	h, err := s.LookupHost(context.Background(), "prod-1")
	require.NoError(t, err)
	require.Equal(t, EpithetPrincipalV1, h.PrincipalMode)
	require.Equal(t, inventoryGeneratedDomain, h.Domain.String())
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
		WithDefaultPrincipalMode(EpithetPrincipalV1))
	require.NoError(t, err)

	h, err := s.LookupHost(context.Background(), "ci-42")
	require.NoError(t, err)
	require.Equal(t, AccountNamePrincipals, h.PrincipalMode)
	require.Equal(t, []string{"ubuntu"}, h.Policy.Accounts)
	require.Empty(t, h.Domain)
}

func TestExactHostCanFallBackFromHashedDefault(t *testing.T) {
	src := `
hosts:
  - name: legacy-1
    principal-mode: account-name
`
	s, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(EpithetPrincipalV1))
	require.NoError(t, err)

	h, err := s.LookupHost(context.Background(), "legacy-1")
	require.NoError(t, err)
	require.Equal(t, AccountNamePrincipals, h.PrincipalMode)
}

func TestHashedExactHostWithoutDomainIsError(t *testing.T) {
	src := "hosts:\n  - name: prod-1\n"
	_, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(EpithetPrincipalV1))
	require.ErrorContains(t, err, "has no domain")
}

func TestHashedPatternLoadsDeclaredNamedDomain(t *testing.T) {
	src := "domains: [production]\nhosts:\n  - pattern: 'prod-*'\n    domain: production\n"
	s, err := NewStatic(
		[]string{writeInv(t, "inv.yaml", src)},
		WithDefaultPrincipalMode(EpithetPrincipalV1))
	require.NoError(t, err)

	host, err := s.LookupHost(context.Background(), "prod-worker-1")
	require.NoError(t, err)
	require.Equal(t, EpithetPrincipalV1, host.PrincipalMode)
	require.Equal(t, "production", host.Domain.String())
	require.Equal(t, "production", host.Policy.Name, "Writ authorizes the shared domain, not one member hostname")
}

func TestPatternWithGeneratedHostDomainIsError(t *testing.T) {
	src := "hosts:\n  - pattern: 'prod-*'\n    principal-mode: account-name\n    domain: " + inventoryGeneratedDomain + "\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "cannot use generated host domain")
}

func TestMalformedDomainIsError(t *testing.T) {
	src := "hosts:\n  - name: prod-1\n    domain: 'not a domain'\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "domain")
}

func TestUndeclaredNamedDomainIsError(t *testing.T) {
	src := "hosts:\n  - pattern: 'prod-*'\n    principal-mode: epithet-principal-v1\n    domain: prodution\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, `references undeclared domain "prodution"`)
}

func TestNamedDomainMayBeDeclaredInLaterFile(t *testing.T) {
	hosts := "hosts:\n  - pattern: 'prod-*'\n    principal-mode: epithet-principal-v1\n    domain: production\n"
	domains := "domains: [production]\n"
	_, err := NewStatic([]string{writeInv(t, "hosts.yaml", hosts), writeInv(t, "domains.yaml", domains)})
	require.NoError(t, err)
}

func TestDuplicateNamedDomainIsError(t *testing.T) {
	one := "domains: [production]\n"
	_, err := NewStatic([]string{writeInv(t, "a.yaml", one), writeInv(t, "b.yaml", one)})
	require.ErrorContains(t, err, `duplicate domain "production"`)
}

func TestNamedDomainRequiresHashedPrincipalMode(t *testing.T) {
	src := "domains: [production]\nhosts:\n  - pattern: 'prod-*'\n    domain: production\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "named domain")
	require.ErrorContains(t, err, string(EpithetPrincipalV1))
}

func TestNamedDomainEntriesMustShareAuthorizationAttributes(t *testing.T) {
	src := `
domains: [production]
hosts:
  - name: prod-1
    domain: production
    principal-mode: epithet-principal-v1
    labels: {role: web}
  - name: prod-2
    domain: production
    principal-mode: epithet-principal-v1
    labels: {role: database}
`
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "different authorization attributes")
}

func TestNamedDomainEntriesResolveToSamePolicyResource(t *testing.T) {
	src := `
domains: [production]
hosts:
  - name: prod-1
    domain: production
    principal-mode: epithet-principal-v1
    labels: {env: prod}
  - name: prod-2
    domain: production
    principal-mode: epithet-principal-v1
    labels: {env: prod}
`
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)

	one, err := s.LookupHost(context.Background(), "prod-1")
	require.NoError(t, err)
	two, err := s.LookupHost(context.Background(), "prod-2")
	require.NoError(t, err)
	require.Equal(t, "production", one.Policy.Name)
	require.Equal(t, one.Policy, two.Policy)
	require.Equal(t, one.Domain, two.Domain)
}

func TestNamedDomainAccountOrderDoesNotChangeAuthorizationAttributes(t *testing.T) {
	src := `
domains: [production]
hosts:
  - name: prod-1
    domain: production
    principal-mode: epithet-principal-v1
    accounts: [root, ubuntu]
  - name: prod-2
    domain: production
    principal-mode: epithet-principal-v1
    accounts: [ubuntu, root]
`
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
}

func TestNamedDomainDistinguishesAbsentAndEmptyAccountGrounding(t *testing.T) {
	src := `
domains: [production]
hosts:
  - name: prod-1
    domain: production
    principal-mode: epithet-principal-v1
  - name: prod-2
    domain: production
    principal-mode: epithet-principal-v1
    accounts: []
`
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "different authorization attributes")
}

func TestUnknownPrincipalModeIsError(t *testing.T) {
	src := "hosts:\n  - name: prod-1\n    principal-mode: mystery\n"
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
  - name: ci-runner-1
    labels: {env: prod}
  - pattern: "ci-runner-*"
    labels: {env: ci}
`
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
	h, err := s.LookupHost(context.Background(), "ci-runner-1")
	require.NoError(t, err)
	require.Equal(t, "prod", h.Policy.Labels["env"])
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
	require.Equal(t, "broad", h.Policy.Labels["tier"], "pattern entries match in file order")
}

func TestEmptyAccountsListStaysNonNil(t *testing.T) {
	src := `
hosts:
  - name: locked-down
    accounts: []
`
	s, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.NoError(t, err)
	h, err := s.LookupHost(context.Background(), "locked-down")
	require.NoError(t, err)
	require.NotNil(t, h.Policy.Accounts, "accounts: [] grounds nothing, which is different from absent")
	require.Empty(t, h.Policy.Accounts)
}

func TestMultipleFilesConcatenate(t *testing.T) {
	users := "users:\n  - userName: alice@example.com\n"
	hosts := "hosts:\n  - name: web-1\n"
	s, err := NewStatic([]string{writeInv(t, "users.yaml", users), writeInv(t, "hosts.yaml", hosts)})
	require.NoError(t, err)
	u, _ := s.LookupUser(context.Background(), "alice@example.com")
	require.NotNil(t, u)
	h, _ := s.LookupHost(context.Background(), "web-1")
	require.NotNil(t, h)
}

func TestDuplicateUserAcrossFilesIsError(t *testing.T) {
	one := "users:\n  - userName: alice@example.com\n"
	_, err := NewStatic([]string{writeInv(t, "a.yaml", one), writeInv(t, "b.yaml", one)})
	require.ErrorContains(t, err, "duplicate user")
}

func TestDuplicateHostIsError(t *testing.T) {
	src := "hosts:\n  - name: web-1\n  - name: WEB-1\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "duplicate host")
}

func TestUnknownFieldIsError(t *testing.T) {
	src := "users:\n  - userName: alice@example.com\n    grops: [SRE]\n"
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", src)})
	require.ErrorContains(t, err, "grops")
}

func TestUserWithoutUserNameIsError(t *testing.T) {
	_, err := NewStatic([]string{writeInv(t, "inv.yaml", "users:\n  - groups: [SRE]\n")})
	require.ErrorContains(t, err, "userName")
}

func TestHostWithNameAndPatternIsError(t *testing.T) {
	src := "hosts:\n  - name: a\n    pattern: \"b*\"\n"
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
