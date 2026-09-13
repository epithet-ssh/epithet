package inventory

import (
	"context"
	"errors"
	"fmt"
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
func TestManagedAdmissionConflictAndWildcardFallback(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n  - pattern: '*.example'\n    accounts: [root]\n")
	a, err := m.Enroll(proposal("a.example"), "")
	require.NoError(t, err)
	b, err := m.Enroll(proposal("a.example"), "")
	require.NoError(t, err)
	h, _, err := m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts, "pending must not change wildcard admission")
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
	h, _, err = m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts)
	a, err = m.Enroll(proposal("a.example"), "")
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	h, _, err = m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Policy.Accounts)
}
func TestManagedTokenAtomicSingleUseAndRestart(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	tok, err := m.CreateToken("admin", time.Hour)
	secret := tok.ID
	require.NoError(t, err)

	h, err := m.Enroll(proposal("one"), secret)
	require.NoError(t, err)
	require.Equal(t, "active", h.Status)
	_, err = m.Enroll(proposal("different"), secret)
	require.ErrorIs(t, err, ErrToken)
	_, err = m.Enroll(proposal("two"), secret)
	require.ErrorIs(t, err, ErrToken)
	data, err := os.ReadFile(m.files.itemPath(h.ID))
	require.NoError(t, err)
	require.Equal(t, secret, h.ID)
	require.Equal(t, tok.ID, h.ID)
	require.Contains(t, string(data), secret)
	require.NotContains(t, string(data), "credential-hash")
	dir := m.files.root
	require.NoError(t, m.Close())
	fresh, err := OpenManaged(dir, m.static)
	require.NoError(t, err)
	defer fresh.Close()
	tokens, err := fresh.Tokens()
	require.NoError(t, err)
	require.Equal(t, tok.ID, tokens[0].ID)
	require.Equal(t, h.ID, tokens[0].UsedBy)
	host, _, err := fresh.LookupHost(context.Background(), "one")
	require.NoError(t, err)
	require.NotNil(t, host)
	_, err = fresh.Change("admin", "remove", h.ID, h.Revision, nil)
	require.NoError(t, err)
	require.NoFileExists(t, fresh.files.itemPath(h.ID))
	require.NoError(t, fresh.Close())
	fresh, err = OpenManaged(dir, m.static)
	require.NoError(t, err)
	defer fresh.Close()
	_, err = fresh.Get(h.ID)
	require.ErrorIs(t, err, ErrNotFound)
	tokens, err = fresh.Tokens()
	require.NoError(t, err)
	require.Empty(t, tokens)
	host, _, err = fresh.LookupHost(t.Context(), "one")
	require.NoError(t, err)
	require.Nil(t, host)
	_, err = fresh.Enroll(proposal("one"), secret)
	require.ErrorIs(t, err, ErrToken, "deleted host must not make its token reusable")
	again, err := fresh.Enroll(proposal("one"), "")
	require.NoError(t, err)
	require.NotEqual(t, h.ID, again.ID)
	require.Equal(t, "pending", again.Status)
}
func TestManagedConcurrentApprovalAndRedemption(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	token, err := m.CreateToken("admin", time.Hour)
	secret := token.ID
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, n := range []string{"a", "b"} {

		wg.Add(1)
		go func() { defer wg.Done(); _, e := m.Enroll(proposal(n), secret); results <- e }()
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
	a, e := m.Enroll(proposal("same"), "")
	require.NoError(t, e)
	b, e := m.Enroll(proposal("same"), "")
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
	pending, err := m.Enroll(proposal("static"), "")
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", pending.ID, pending.Revision, nil)
	require.ErrorIs(t, err, ErrConflict)
	h, err := m.Enroll(proposal("dynamic"), "")
	require.NoError(t, err)
	// Force a failed rename. Uncommitted approval must never become readable.
	require.NoError(t, os.Remove(m.files.itemPath(h.ID)))
	require.NoError(t, os.Mkdir(m.files.itemPath(h.ID), 0700))
	_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.Error(t, err)
	_, _, err = m.LookupHost(context.Background(), "dynamic")
	require.Error(t, err)
	_, _, err = m.LookupHost(context.Background(), "static")
	require.ErrorIs(t, err, ErrStorage, "a failed managed store must not switch to static-only service")
}
func TestManagedRevisionLockAndValidation(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	_, err := OpenManaged(m.files.root, m.static)
	require.Error(t, err)
	h, err := m.Enroll(proposal("A.example"), "")
	require.NoError(t, err)
	require.Equal(t, []string{"a.example"}, h.Proposal.Names)
	p := proposal("other")
	_, err = m.Change("admin", "edit", h.ID, h.Revision, &p)
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.ErrorIs(t, err, ErrRevision)
	for _, body := range []string{"names: [a]\nprincipal-mode: account-name\n", "names: [a]\naccounts: []\nprincipal-mode: account-name\nstatus: active\n", "names: [a]\naccounts: []\nprincipal-mode: account-name\n---\n{}"} {
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
	token, err := m.CreateToken("admin", time.Hour)
	secret := token.ID
	require.NoError(t, err)
	_, err = m.Enroll(proposal("taken"), secret)
	require.ErrorIs(t, err, ErrConflict)
	_, err = m.Enroll(proposal("free"), secret)
	require.NoError(t, err)
	tok, err := m.CreateToken("admin", time.Hour)
	secret = tok.ID
	require.NoError(t, err)
	require.NoError(t, m.RevokeToken("admin", tok.ID))
	_, err = m.Enroll(proposal("revoked"), secret)
	require.ErrorIs(t, err, ErrToken)
	expiredToken, err := m.CreateToken("admin", time.Nanosecond)
	secret = expiredToken.ID
	require.NoError(t, err)
	time.Sleep(time.Millisecond)
	_, err = m.Enroll(proposal("expired"), secret)
	require.ErrorIs(t, err, ErrToken)
}
func TestManagedRejectCorruptState(t *testing.T) {
	dir := t.TempDir()
	records := filepath.Join(dir, "records")
	require.NoError(t, os.Mkdir(records, 0700))
	path := filepath.Join(records, strings.Repeat("a", 64)+".yaml")
	for _, invalid := range []string{"version: 99\n", "version: 2\nunknown: foo\n"} {
		require.NoError(t, os.WriteFile(path, []byte(invalid), 0600))
		_, err := OpenManaged(dir, nil)
		require.ErrorContains(t, err, "opening managed inventory")
		require.False(t, errors.Is(err, ErrNotFound))
	}
}

func TestManagedCorruptionFailsStartupEvenWithStaticOverrides(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [recovery]\n   accounts: [root]\n - pattern: '*'\n")
	dir := m.files.root
	require.NoError(t, m.Close())
	path := filepath.Join(m.files.dir, strings.Repeat("a", 64)+".yaml")
	require.NoError(t, os.WriteFile(path, []byte("not valid: ["), 0600))
	failed, err := OpenManaged(dir, m.static)
	require.ErrorContains(t, err, "opening managed inventory")
	require.Nil(t, failed)
	// Failed startup releases the lock, so repairing the file allows startup.
	require.NoError(t, os.Remove(path))
	repaired, err := OpenManaged(dir, m.static)
	require.NoError(t, err)
	defer repaired.Close()
	host, _, err := repaired.LookupHost(t.Context(), "recovery")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, host.Policy.Accounts)
}

func TestManagedSnapshotsDoNotExposeMutableState(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	p := proposal("host")
	p.Labels = map[string]string{"role": "server"}

	h, err := m.Enroll(p, "")
	require.NoError(t, err)
	p.Labels["role"] = "hijacked"
	h.Proposal.Accounts[0] = "root"
	retry, err := m.Get(h.ID)
	require.NoError(t, err)
	retry.Proposal.Labels["role"] = "hijacked"
	h, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	host, revision, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.NotEmpty(t, revision)
	require.Equal(t, "server", host.Policy.Labels["role"])
	require.Equal(t, []string{"alice"}, host.Policy.Accounts)
	host.Policy.Labels["role"] = "hijacked"
	next, _, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.Equal(t, "server", next.Policy.Labels["role"])
}

func TestManagedApprovalRejectsSharedGeneratedDomains(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	p := proposal("first")
	p.PrincipalMode = EpithetPrincipalV1
	p.Domain = "epithet-host-id-v1:" + strings.Repeat("A", 43)
	a, err := m.Enroll(p, "")
	require.NoError(t, err)
	p.Names = []string{"second"}
	b, err := m.Enroll(p, "")
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", b.ID, b.Revision, nil)
	require.ErrorIs(t, err, ErrConflict)
}

func TestManagedSharedDomainMembership(t *testing.T) {
	m, _ := managedFixture(t, "domains: [fleet, other]\n")
	p := proposal("first")
	p.PrincipalMode, p.Domain = EpithetPrincipalV1, "fleet"
	p.Accounts = []string{"alice", "root"}
	a, err := m.Enroll(p, "")
	require.NoError(t, err)
	a, err = m.Change("admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	p.Names, p.Accounts = []string{"second"}, []string{"root", "alice"}
	token, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	b, err := m.Enroll(p, token.ID)
	require.NoError(t, err)
	require.Equal(t, "active", b.Status)
	require.NoError(t, m.Close())
	fresh, err := OpenManaged(m.files.root, m.static)
	require.NoError(t, err)
	defer fresh.Close()
	for _, name := range []string{"first", "second"} {
		h, _, err := fresh.LookupHost(t.Context(), name)
		require.NoError(t, err)
		require.Equal(t, "fleet", string(h.Domain))
		require.Equal(t, []string{"fleet"}, h.Policy.Names)
	}

	// One member cannot change the shared authorization attributes.
	p.Accounts = []string{"root"}
	_, err = fresh.Change("admin", "edit", b.ID, b.Revision, &p)
	require.ErrorIs(t, err, ErrConflict)
	// Moving that member releases its old domain membership, without losing
	// the remaining member's constraints.
	p.Domain = "other"
	b, err = fresh.Change("admin", "edit", b.ID, b.Revision, &p)
	require.NoError(t, err)
	h, _, err := fresh.LookupHost(t.Context(), "second")
	require.NoError(t, err)
	require.Equal(t, []string{"other"}, h.Policy.Names)
	p.Domain, p.Names = "fleet", []string{"third"}
	c, err := fresh.Enroll(p, "")
	require.NoError(t, err)
	_, err = fresh.Change("admin", "approve", c.ID, c.Revision, nil)
	require.ErrorIs(t, err, ErrConflict)
	_, err = fresh.Change("admin", "remove", a.ID, a.Revision, nil)
	require.NoError(t, err)
	_, err = fresh.Change("admin", "approve", c.ID, c.Revision, nil)
	require.NoError(t, err, "the last member's removal releases its authorization attributes")
}

func TestManagedSharedDomainMatchesStaticMembers(t *testing.T) {
	for _, selector := range []string{"names: [static]", "pattern: '*.example'"} {
		t.Run(selector, func(t *testing.T) {
			m, _ := managedFixture(t, "domains: [fleet]\nhosts:\n - "+selector+"\n   principal-mode: epithet-principal-v1\n   domain: fleet\n   accounts: []\n   labels: {role: server}\n")
			p := proposal("dynamic")
			p.PrincipalMode, p.Domain = EpithetPrincipalV1, "fleet"
			p.Labels = map[string]string{"role": "server"}
			p.Accounts = nil
			h, err := m.Enroll(p, "")
			require.NoError(t, err)
			_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
			require.ErrorIs(t, err, ErrConflict, "null must differ from []")
			p.Accounts, p.Labels = []string{}, map[string]string{"role": "client"}
			h, err = m.Change("admin", "edit", h.ID, h.Revision, &p)
			require.NoError(t, err)
			_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
			require.ErrorIs(t, err, ErrConflict)
			p.Labels = map[string]string{"role": "server"}
			h, err = m.Change("admin", "edit", h.ID, h.Revision, &p)
			require.NoError(t, err)
			_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
			require.NoError(t, err)
			require.NoError(t, m.Close())
			fresh, err := OpenManaged(m.files.root, m.static)
			require.NoError(t, err)
			require.NoError(t, fresh.Close())
		})
	}
}

func TestManagedSharedDomainValidation(t *testing.T) {
	m, _ := managedFixture(t, "domains: [fleet]\n")
	p := proposal("host")
	p.Domain = "fleet"
	_, err := m.Enroll(p, "")
	require.ErrorContains(t, err, "requires epithet-principal-v1")
	p.PrincipalMode, p.Domain = EpithetPrincipalV1, "typo"
	h, err := m.Enroll(p, "")
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.ErrorContains(t, err, "undeclared domain")
	p.Domain = "not a domain"
	_, err = m.Enroll(p, "")
	require.Error(t, err)
}

func TestManagedAccountSemanticsSurviveRestart(t *testing.T) {
	for _, accounts := range [][]string{nil, {}, {"alice"}} {
		t.Run(fmt.Sprintf("%#v", accounts), func(t *testing.T) {
			m, _ := managedFixture(t, "users: []\n")
			p := proposal("host")
			p.Accounts = accounts
			h, err := m.Enroll(p, "")
			require.NoError(t, err)
			_, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
			require.NoError(t, err)
			require.NoError(t, m.Close())
			fresh, err := OpenManaged(m.files.root, m.static)
			require.NoError(t, err)
			defer fresh.Close()
			host, _, err := fresh.LookupHost(t.Context(), "host")
			require.NoError(t, err)
			require.Equal(t, accounts, host.Policy.Accounts)
		})
	}
}

func TestPendingConflictsAreResolvedBeforeApproval(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [static]\n   accounts: [root]\n")
	approved, err := m.Enroll(proposal("taken"), "")
	require.NoError(t, err)
	approved, err = m.Change("admin", "approve", approved.ID, approved.Revision, nil)
	require.NoError(t, err)
	pending, err := m.Enroll(proposal("taken"), "")
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Status)
	_, err = m.Change("admin", "approve", pending.ID, pending.Revision, nil)
	require.ErrorIs(t, err, ErrConflict)

	// Editing the existing record can release the name for the pending request.
	moved := proposal("moved")
	_, err = m.Change("admin", "edit", approved.ID, approved.Revision, &moved)
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", pending.ID, pending.Revision, nil)
	require.NoError(t, err)

	pending, err = m.Enroll(proposal("static"), "")
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", pending.ID, pending.Revision, nil)
	require.ErrorIs(t, err, ErrConflict)
	current, _, err := m.LookupHost(t.Context(), "static")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, current.Policy.Accounts)

	// Editing the pending request can resolve a conflict with a static record.
	moved = proposal("free")
	pending, err = m.Change("admin", "edit", pending.ID, pending.Revision, &moved)
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", pending.ID, pending.Revision, nil)
	require.NoError(t, err)
}

func TestUnapprovedRecordsNeverAffectResolution(t *testing.T) {
	for _, action := range []string{"pending", "deny", "remove", "deny-then-remove"} {
		t.Run(action, func(t *testing.T) {
			m, _ := managedFixture(t, "hosts:\n - pattern: '*.example'\n   accounts: [root]\n")
			accepted, err := m.Enroll(proposal("accepted.example"), "")
			require.NoError(t, err)
			_, err = m.Change("admin", "approve", accepted.ID, accepted.Revision, nil)
			require.NoError(t, err)

			pending, err := m.Enroll(proposal("old.example"), "")
			require.NoError(t, err)
			edited := proposal("new.example")
			edited.Names = append(edited.Names, "accepted.example")
			pending, err = m.Change("admin", "edit", pending.ID, pending.Revision, &edited)
			require.NoError(t, err)
			if action == "deny" || action == "deny-then-remove" {
				pending, err = m.Change("admin", "deny", pending.ID, pending.Revision, nil)
				require.NoError(t, err)
			}
			if action == "remove" || action == "deny-then-remove" {
				_, err = m.Change("admin", "remove", pending.ID, pending.Revision, nil)
				require.NoError(t, err)
			}
			check := func(store *Managed) {
				for _, name := range []string{"old.example", "new.example"} {
					h, _, err := store.LookupHost(t.Context(), name)
					require.NoError(t, err)
					require.NotNil(t, h)
					require.Equal(t, []string{"root"}, h.Policy.Accounts)
				}
				h, _, err := store.LookupHost(t.Context(), "accepted.example")
				require.NoError(t, err)
				require.Equal(t, []string{"alice"}, h.Policy.Accounts)
			}
			check(m)
			require.NoError(t, m.Close())
			restarted, err := OpenManaged(m.files.root, m.static)
			require.NoError(t, err)
			defer restarted.Close()
			check(restarted)
		})
	}
}
