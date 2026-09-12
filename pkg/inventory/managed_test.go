package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func managedFixture(t *testing.T, staticYAML string) (*Managed, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "static.yaml")
	require.NoError(t, os.WriteFile(path, []byte(staticYAML), 0600))
	s, err := NewStatic([]string{path})
	require.NoError(t, err)
	m, err := OpenManaged(filepath.Join(dir, "state"), s)
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m, dir
}
func proposal(name string) Proposal {
	return Proposal{Names: []string{name}, Labels: map[string]string{}, Accounts: []string{"alice"}, PrincipalMode: AccountNamePrincipals}
}
func credential(t *testing.T) string {
	t.Helper()
	v, e := RandomSecret()
	require.NoError(t, e)
	return v
}
func TestManagedAdmissionConflictAndWildcardTombstones(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n  - pattern: '*.example'\n    accounts: [root]\n")
	a, err := m.Enroll(proposal("a.example"), credential(t), "")
	require.NoError(t, err)
	b, err := m.Enroll(proposal("a.example"), credential(t), "")
	require.NoError(t, err)
	h, err := m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Nil(t, h, "pending must mask wildcard")
	a, err = m.Change("admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", b.ID, b.Revision, nil)
	require.ErrorIs(t, err, ErrConflict)
	p := proposal("b.example")
	b, err = m.Change("admin", "edit", b.ID, b.Revision, &p)
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", b.ID, b.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change("admin", "remove", a.ID, a.Revision, nil)
	require.NoError(t, err)
	h, err = m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Nil(t, h)
	a, err = m.Enroll(proposal("a.example"), credential(t), "")
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	h, err = m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Policy.Accounts)
}
func TestManagedTokenAtomicSingleUseRestartAndRetry(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	tok, secret, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	key := credential(t)
	h, err := m.Enroll(proposal("one"), key, secret)
	require.NoError(t, err)
	require.Equal(t, "approved", h.Status)
	again, err := m.Enroll(proposal("different"), key, secret)
	require.NoError(t, err)
	require.Equal(t, h.ID, again.ID)
	require.Equal(t, []string{"one"}, again.Proposal.Names)
	_, err = m.Enroll(proposal("two"), credential(t), secret)
	require.ErrorIs(t, err, ErrToken)
	data, err := os.ReadFile(m.path)
	require.NoError(t, err)
	require.NotContains(t, string(data), secret)
	require.NotContains(t, string(data), key)
	dir := filepath.Dir(m.path)
	require.NoError(t, m.Close())
	fresh, err := OpenManaged(dir, m.static)
	require.NoError(t, err)
	defer fresh.Close()
	tokens, err := fresh.Tokens()
	require.NoError(t, err)
	require.Equal(t, tok.ID, tokens[0].ID)
	require.Equal(t, h.ID, tokens[0].UsedBy)
	host, err := fresh.LookupHost(context.Background(), "one")
	require.NoError(t, err)
	require.NotNil(t, host)
	_, err = fresh.Change("admin", "remove", h.ID, h.Revision, nil)
	require.NoError(t, err)
	_, err = fresh.Enroll(proposal("one"), key, secret)
	require.ErrorIs(t, err, ErrToken, "used token must not restore admission")
	again, err = fresh.Enroll(proposal("one"), key, "")
	require.NoError(t, err)
	require.NotEqual(t, h.ID, again.ID)
	require.Equal(t, "pending", again.Status)
}
func TestManagedConcurrentApprovalAndRedemption(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	_, secret, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, n := range []string{"a", "b"} {
		key := credential(t)
		wg.Add(1)
		go func() { defer wg.Done(); _, e := m.Enroll(proposal(n), key, secret); results <- e }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		} else {
			require.ErrorIs(t, e, ErrToken)
		}
	}
	require.Equal(t, 1, successes)
	a, e := m.Enroll(proposal("same"), credential(t), "")
	require.NoError(t, e)
	b, e := m.Enroll(proposal("same"), credential(t), "")
	require.NoError(t, e)
	results = make(chan error, 2)
	for _, h := range []*HostRecord{a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := m.Change("admin", "approve", h.ID, h.Revision, nil); results <- e }()
	}
	wg.Wait()
	close(results)
	successes = 0
	for e := range results {
		if e == nil {
			successes++
		} else {
			require.ErrorIs(t, e, ErrConflict)
		}
	}
	require.Equal(t, 1, successes)
}
func TestManagedStaticPrecedenceAndStorageFailure(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [static]\n   accounts: [root]\n - pattern: '*'\n   accounts: [fallback]\n")
	_, err := m.Enroll(proposal("static"), credential(t), "")
	require.ErrorIs(t, err, ErrConflict)
	h, err := m.Enroll(proposal("dynamic"), credential(t), "")
	require.NoError(t, err)
	// Force a failed rename. Uncommitted approval must never become readable.
	require.NoError(t, os.Remove(m.path))
	require.NoError(t, os.Mkdir(m.path, 0700))
	_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.Error(t, err)
	_, err = m.LookupHost(context.Background(), "dynamic")
	require.Error(t, err)
	static, err := m.LookupHost(context.Background(), "static")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, static.Policy.Accounts)
}
func TestManagedRevisionLockAndValidation(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	_, err := OpenManaged(filepath.Dir(m.path), m.static)
	require.Error(t, err)
	h, err := m.Enroll(proposal("A.example"), credential(t), "")
	require.NoError(t, err)
	require.Equal(t, []string{"a.example"}, h.Proposal.Names)
	p := proposal("other")
	_, err = m.Change("admin", "edit", h.ID, h.Revision, &p)
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.ErrorIs(t, err, ErrRevision)
	for _, body := range []string{"names: [a]\nprincipal-mode: account-name\n", "names: [a]\naccounts: []\nprincipal-mode: account-name\nstatus: approved\n", "names: [a]\naccounts: []\nprincipal-mode: account-name\n---\n{}"} {
		_, err := ParseProposal([]byte(body))
		require.Error(t, err)
	}
	p, err = ParseProposal([]byte("names: [a]\naccounts: null\nprincipal-mode: account-name\n"))
	require.NoError(t, err)
	require.Nil(t, p.Accounts)
	p, err = ParseProposal([]byte("names: [a]\naccounts: []\nprincipal-mode: account-name\n"))
	require.NoError(t, err)
	require.NotNil(t, p.Accounts)
}
func TestManagedTokenConflictDoesNotConsumeAndExpiry(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [taken]\n")
	_, secret, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	_, err = m.Enroll(proposal("taken"), credential(t), secret)
	require.ErrorIs(t, err, ErrConflict)
	_, err = m.Enroll(proposal("free"), credential(t), secret)
	require.NoError(t, err)
	tok, secret, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	require.NoError(t, m.RevokeToken("admin", tok.ID))
	_, err = m.Enroll(proposal("revoked"), credential(t), secret)
	require.ErrorIs(t, err, ErrToken)
	_, secret, err = m.CreateToken("admin", time.Nanosecond)
	require.NoError(t, err)
	time.Sleep(time.Millisecond)
	_, err = m.Enroll(proposal("expired"), credential(t), secret)
	require.ErrorIs(t, err, ErrToken)
}
func TestManagedRejectCorruptState(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "inventory.yaml"), []byte("version: 99\n"), 0600))
	_, err := OpenManaged(dir, nil)
	require.Error(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "inventory.yaml"), []byte("version: 1\nunknown: foo\n"), 0600))
	_, err = OpenManaged(dir, nil)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrNotFound))
	require.True(t, strings.Contains(err.Error(), "opening managed inventory"))
}

func TestManagedCorruptionKeepsStaticRecoveryAvailable(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [recovery]\n   accounts: [root]\n - pattern: '*'\n")
	dir := filepath.Dir(m.path)
	require.NoError(t, m.Close())
	require.NoError(t, os.WriteFile(m.path, []byte("not valid: ["), 0600))
	fallback, err := OpenManagedWithStaticFallback(dir, m.static)
	require.NoError(t, err)
	defer fallback.Close()
	require.ErrorIs(t, fallback.Health(), ErrStorage)
	h, err := fallback.LookupHost(t.Context(), "recovery")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts)
	_, err = fallback.LookupHost(t.Context(), "anything")
	require.ErrorIs(t, err, ErrStorage)
	_, err = fallback.Enroll(proposal("new"), credential(t), "")
	require.ErrorIs(t, err, ErrStorage)
}

func TestManagedSnapshotsDoNotExposeMutableState(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	p := proposal("host")
	p.Labels = map[string]string{"role": "server"}
	key := credential(t)
	h, err := m.Enroll(p, key, "")
	require.NoError(t, err)
	p.Labels["role"] = "hijacked"
	h.Proposal.Accounts[0] = "root"
	retry, err := m.Enroll(proposal("ignored"), key, "")
	require.NoError(t, err)
	retry.Proposal.Labels["role"] = "hijacked"
	h, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	host, revision, err := m.LookupHostSnapshot(t.Context(), "host")
	require.NoError(t, err)
	require.NotEmpty(t, revision)
	require.Equal(t, "server", host.Policy.Labels["role"])
	require.Equal(t, []string{"alice"}, host.Policy.Accounts)
	host.Policy.Labels["role"] = "hijacked"
	next, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.Equal(t, "server", next.Policy.Labels["role"])
}

func TestManagedApprovalRejectsSharedGeneratedDomains(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	p := proposal("first")
	p.PrincipalMode = EpithetPrincipalV1
	p.Domain = "epithet-host-id-v1:" + strings.Repeat("A", 43)
	a, err := m.Enroll(p, credential(t), "")
	require.NoError(t, err)
	p.Names = []string{"second"}
	b, err := m.Enroll(p, credential(t), "")
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", b.ID, b.Revision, nil)
	require.ErrorIs(t, err, ErrConflict)
}
