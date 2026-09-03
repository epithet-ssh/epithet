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
	h, err := s.LookupHost(context.Background(), "ci-runner-42.internal")
	require.NoError(t, err)
	require.NotNil(t, h, "glob crosses dots")
	require.Equal(t, "ci-runner-42.internal", h.Policy.Name, "synthesized host adopts the requested name")
	require.Equal(t, "ci", h.Policy.Labels["env"])
	require.Nil(t, h.Policy.Accounts)
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
