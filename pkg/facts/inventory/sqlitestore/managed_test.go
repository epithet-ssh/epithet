package sqlitestore

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

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func managedFixture(t *testing.T, initialYAML string) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state", "inventory.db")
	m, err := Open(dbPath)
	require.NoError(t, err)
	var initial struct {
		Hosts []struct {
			Names         []string                `yaml:"names"`
			Pattern       string                  `yaml:"pattern"`
			Labels        map[string]string       `yaml:"labels"`
			Accounts      []string                `yaml:"accounts"`
			PrincipalMode inventory.PrincipalMode `yaml:"principal-mode"`
			Realm         string                  `yaml:"realm"`
		} `yaml:"hosts"`
		Users []yaml.Node `yaml:"users"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(initialYAML), &initial))
	for _, h := range initial.Hosts {
		p := inventory.Proposal{Names: h.Names, Pattern: h.Pattern, Labels: h.Labels, Accounts: h.Accounts, PrincipalMode: h.PrincipalMode.Effective(), Realm: h.Realm}
		record, err := m.Enroll(t.Context(), p, "")
		require.NoError(t, err)
		_, err = m.Change(t.Context(), "admin", "approve", record.ID, record.Revision, nil)
		require.NoError(t, err)
	}
	t.Cleanup(func() { m.Close() })
	return m, dbPath
}
func proposal(name string) inventory.Proposal {
	return inventory.Proposal{Names: []string{name}, Labels: map[string]string{}, Accounts: []string{"alice"}, PrincipalMode: inventory.AccountNamePrincipals}
}
func TestManagedAdmissionConflictAndWildcardFallback(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n  - pattern: '*.example'\n    accounts: [root]\n")
	a, err := m.Enroll(t.Context(), proposal("a.example"), "")
	require.NoError(t, err)
	b, err := m.Enroll(t.Context(), proposal("a.example"), "")
	require.NoError(t, err)
	h, _, err := m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts, "pending must not change wildcard admission")
	a, err = m.Change(t.Context(), "admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", b.ID, b.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)
	p := proposal("b.example")
	b, err = m.Change(t.Context(), "admin", "edit", b.ID, b.Revision, &p)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", b.ID, b.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "remove", a.ID, a.Revision, nil)
	require.NoError(t, err)
	h, _, err = m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Policy.Accounts)
	a, err = m.Enroll(t.Context(), proposal("a.example"), "")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	h, _, err = m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Policy.Accounts)
}
func TestManagedTokenAtomicSingleUseAndRestart(t *testing.T) {
	m, path := managedFixture(t, "")
	tok, err := m.CreateToken(t.Context(), "admin", time.Hour)
	secret := tok.ID
	require.NoError(t, err)

	h, err := m.Enroll(t.Context(), proposal("one"), secret)
	require.NoError(t, err)
	require.Equal(t, "active", h.Status)
	_, err = m.Enroll(t.Context(), proposal("different"), secret)
	require.ErrorIs(t, err, inventory.ErrToken)
	_, err = m.Enroll(t.Context(), proposal("two"), secret)
	require.ErrorIs(t, err, inventory.ErrToken)
	require.Equal(t, secret, h.ID)
	require.Equal(t, tok.ID, h.ID)
	require.NoError(t, m.Close())
	fresh, err := Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	tokens, err := fresh.Tokens(t.Context())
	require.NoError(t, err)
	require.Equal(t, tok.ID, tokens[0].ID)
	require.Equal(t, h.ID, tokens[0].UsedBy)
	host, _, err := fresh.LookupHost(context.Background(), "one")
	require.NoError(t, err)
	require.NotNil(t, host)
	_, err = fresh.Change(t.Context(), "admin", "remove", h.ID, h.Revision, nil)
	require.NoError(t, err)
	require.NoError(t, fresh.Close())
	fresh, err = Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	_, err = fresh.Get(t.Context(), h.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	tokens, err = fresh.Tokens(t.Context())
	require.NoError(t, err)
	require.Empty(t, tokens)
	host, _, err = fresh.LookupHost(t.Context(), "one")
	require.NoError(t, err)
	require.Nil(t, host)
	_, err = fresh.Enroll(t.Context(), proposal("one"), secret)
	require.ErrorIs(t, err, inventory.ErrToken, "deleted host must not make its token reusable")
	again, err := fresh.Enroll(t.Context(), proposal("one"), "")
	require.NoError(t, err)
	require.NotEqual(t, h.ID, again.ID)
	require.Equal(t, "pending", again.Status)
}
func TestManagedConcurrentApprovalAndRedemption(t *testing.T) {
	m, path := managedFixture(t, "")
	other, err := Open(path)
	require.NoError(t, err)
	defer other.Close()
	token, err := m.CreateToken(t.Context(), "admin", time.Hour)
	secret := token.ID
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, n := range []string{"a", "b"} {
		store := []*Store{m, other}[i]
		wg.Add(1)
		go func() { defer wg.Done(); _, e := store.Enroll(t.Context(), proposal(n), secret); results <- e }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		} else {
			require.ErrorIs(t, e, inventory.ErrToken)
		}
	}
	require.Equal(t, 1, successes)
	a, e := m.Enroll(t.Context(), proposal("same"), "")
	require.NoError(t, e)
	b, e := m.Enroll(t.Context(), proposal("same"), "")
	require.NoError(t, e)
	results = make(chan error, 2)
	for i, h := range []*inventory.HostRecord{a, b} {
		store := []*Store{m, other}[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := store.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	successes = 0
	for e := range results {
		if e == nil {
			successes++
		} else {
			require.ErrorIs(t, e, inventory.ErrConflict)
		}
	}
	require.Equal(t, 1, successes)
}
func TestManagedExactConflictAndStorageFailure(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [static]\n   accounts: [root]\n - pattern: '*'\n   accounts: [fallback]\n")
	pending, err := m.Enroll(t.Context(), proposal("static"), "")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)
	h, err := m.Enroll(t.Context(), proposal("dynamic"), "")
	require.NoError(t, err)
	// A failed audit insert must roll back the approval and name changes.
	_, err = m.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrStorage)
	current, err := m.Get(t.Context(), h.ID)
	require.NoError(t, err)
	require.Equal(t, h, current)
	_, err = m.db.Exec("DROP TRIGGER fail_audit")
	require.NoError(t, err)
	h, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	for _, name := range []string{"dynamic", "static", "fallback"} {
		_, _, err = m.LookupHost(context.Background(), name)
		require.ErrorIs(t, err, inventory.ErrStorage, "an unavailable database must not switch to a separate fallback")
	}
}
func TestManagedRevisionAndValidation(t *testing.T) {
	m, path := managedFixture(t, "")
	other, err := Open(path)
	require.NoError(t, err)
	defer other.Close()
	h, err := m.Enroll(t.Context(), proposal("A.example"), "")
	require.NoError(t, err)
	require.Equal(t, []string{"a.example"}, h.Proposal.Names)
	p := proposal("other")
	_, err = m.Change(t.Context(), "admin", "edit", h.ID, h.Revision, &p)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrRevision)
	for _, body := range []string{"names: [a]\nprincipal-mode: account-name\n", "names: [a]\naccounts: []\nprincipal-mode: account-name\nstatus: active\n", "names: [a]\naccounts: []\nprincipal-mode: account-name\n---\n{}"} {
		_, err := inventory.ParseProposal([]byte(body))
		require.Error(t, err)
	}
	p, err = inventory.ParseProposal([]byte("names: [a]\naccounts: null\nprincipal-mode: account-name\n"))
	require.NoError(t, err)
	require.Nil(t, p.Accounts)
	p, err = inventory.ParseProposal([]byte("names: [a]\naccounts: []\nprincipal-mode: account-name\n"))
	require.NoError(t, err)
	require.NotNil(t, p.Accounts)
}
func TestManagedTokenConflictDoesNotConsumeAndExpiry(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [taken]\n")
	token, err := m.CreateToken(t.Context(), "admin", time.Hour)
	secret := token.ID
	require.NoError(t, err)
	_, err = m.Enroll(t.Context(), proposal("taken"), secret)
	require.ErrorIs(t, err, inventory.ErrConflict)
	_, err = m.Enroll(t.Context(), proposal("free"), secret)
	require.NoError(t, err)
	tok, err := m.CreateToken(t.Context(), "admin", time.Hour)
	secret = tok.ID
	require.NoError(t, err)
	require.NoError(t, m.RevokeToken(t.Context(), "admin", tok.ID))
	_, err = m.Enroll(t.Context(), proposal("revoked"), secret)
	require.ErrorIs(t, err, inventory.ErrToken)
	expiredToken, err := m.CreateToken(t.Context(), "admin", time.Nanosecond)
	secret = expiredToken.ID
	require.NoError(t, err)
	time.Sleep(time.Millisecond)
	_, err = m.Enroll(t.Context(), proposal("expired"), secret)
	require.ErrorIs(t, err, inventory.ErrToken)
}
func TestManagedRejectCorruptState(t *testing.T) {
	for _, initialYAML := range []string{"", "hosts:\n - names: [recovery]\n   accounts: [root]\n - pattern: '*'\n"} {
		m, path := managedFixture(t, initialYAML)
		require.NoError(t, m.Close())
		require.NoError(t, os.WriteFile(path, []byte("not a database"), 0600))
		failed, err := Open(path)
		require.ErrorContains(t, err, "opening managed inventory")
		require.False(t, errors.Is(err, inventory.ErrNotFound))
		require.Nil(t, failed)
	}
}

func TestManagedSnapshotsDoNotExposeMutableState(t *testing.T) {
	m, _ := managedFixture(t, "")
	p := proposal("host")
	p.Labels = map[string]string{"role": "server"}

	h, err := m.Enroll(t.Context(), p, "")
	require.NoError(t, err)
	p.Labels["role"] = "hijacked"
	h.Proposal.Accounts[0] = "root"
	retry, err := m.Get(t.Context(), h.ID)
	require.NoError(t, err)
	retry.Proposal.Labels["role"] = "hijacked"
	h, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
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

func TestManagedApprovalRejectsSharedGeneratedRealms(t *testing.T) {
	m, _ := managedFixture(t, "")
	p := proposal("first")
	p.PrincipalMode = inventory.EpithetPrincipalV1
	p.Realm = "epithet-host-id-v1:" + strings.Repeat("A", 43)
	a, err := m.Enroll(t.Context(), p, "")
	require.NoError(t, err)
	p.Names = []string{"second"}
	b, err := m.Enroll(t.Context(), p, "")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", b.ID, b.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)
}

func TestManagedSharedRealmMembership(t *testing.T) {
	m, path := managedFixture(t, "")
	p := proposal("first")
	p.PrincipalMode, p.Realm = inventory.EpithetPrincipalV1, "fleet"
	p.Accounts = []string{"alice", "root"}
	p.Names = []string{"first", "first.example.com"}
	a, err := m.Enroll(t.Context(), p, "")
	require.NoError(t, err)
	a, err = m.Change(t.Context(), "admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	p.Names, p.Accounts = []string{"second"}, []string{"root", "alice"}
	token, err := m.CreateToken(t.Context(), "admin", time.Hour)
	require.NoError(t, err)
	b, err := m.Enroll(t.Context(), p, token.ID)
	require.NoError(t, err)
	require.Equal(t, "active", b.Status)
	require.NoError(t, m.Close())
	fresh, err := Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	for _, names := range [][]string{{"first", "first.example.com"}, {"second"}} {
		for _, name := range names {
			h, _, err := fresh.LookupHost(t.Context(), name)
			require.NoError(t, err)
			require.Equal(t, "fleet", string(h.Realm))
			require.Equal(t, names, h.Policy.Names)
		}
	}

	// One member cannot change the shared authorization attributes.
	p.Accounts = []string{"root"}
	_, err = fresh.Change(t.Context(), "admin", "edit", b.ID, b.Revision, &p)
	require.ErrorIs(t, err, inventory.ErrConflict)
	// Moving that member releases its old realm membership, without losing
	// the remaining member's constraints.
	p.Realm = "other"
	b, err = fresh.Change(t.Context(), "admin", "edit", b.ID, b.Revision, &p)
	require.NoError(t, err)
	h, _, err := fresh.LookupHost(t.Context(), "second")
	require.NoError(t, err)
	require.Equal(t, []string{"second"}, h.Policy.Names)
	require.Equal(t, "other", string(h.Realm))
	p.Realm, p.Names = "fleet", []string{"third"}
	c, err := fresh.Enroll(t.Context(), p, "")
	require.NoError(t, err)
	_, err = fresh.Change(t.Context(), "admin", "approve", c.ID, c.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)
	_, err = fresh.Change(t.Context(), "admin", "remove", a.ID, a.Revision, nil)
	require.NoError(t, err)
	_, err = fresh.Change(t.Context(), "admin", "approve", c.ID, c.Revision, nil)
	require.NoError(t, err, "the last member's removal releases its authorization attributes")
}

func TestManagedSharedRealmMatchesExistingMembers(t *testing.T) {
	for _, selector := range []string{"names: [static]", "pattern: '*.example'"} {
		t.Run(selector, func(t *testing.T) {
			m, path := managedFixture(t, "hosts:\n - "+selector+"\n   principal-mode: epithet-principal-v1\n   realm: fleet\n   accounts: []\n   labels: {role: server}\n")
			p := proposal("dynamic")
			p.PrincipalMode, p.Realm = inventory.EpithetPrincipalV1, "fleet"
			p.Labels = map[string]string{"role": "server"}
			p.Accounts = nil
			h, err := m.Enroll(t.Context(), p, "")
			require.NoError(t, err)
			_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
			require.ErrorIs(t, err, inventory.ErrConflict, "null must differ from []")
			p.Accounts, p.Labels = []string{}, map[string]string{"role": "client"}
			h, err = m.Change(t.Context(), "admin", "edit", h.ID, h.Revision, &p)
			require.NoError(t, err)
			_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
			require.ErrorIs(t, err, inventory.ErrConflict)
			p.Labels = map[string]string{"role": "server"}
			h, err = m.Change(t.Context(), "admin", "edit", h.ID, h.Revision, &p)
			require.NoError(t, err)
			_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
			require.NoError(t, err)
			require.NoError(t, m.Close())
			fresh, err := Open(path)
			require.NoError(t, err)
			require.NoError(t, fresh.Close())
		})
	}
}

func TestManagedSharedRealmValidation(t *testing.T) {
	m, _ := managedFixture(t, "")
	p := proposal("host")
	p.Realm = "fleet"
	_, err := m.Enroll(t.Context(), p, "")
	require.ErrorContains(t, err, "requires epithet-principal-v1")
	p.PrincipalMode, p.Realm = inventory.EpithetPrincipalV1, "NewFleet"
	h, err := m.Enroll(t.Context(), p, "")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err, "a named realm needs no separate declaration")
	p.Realm = "not a realm"
	_, err = m.Enroll(t.Context(), p, "")
	require.Error(t, err)
}

func TestManagedAccountSemanticsSurviveRestart(t *testing.T) {
	for _, accounts := range [][]string{nil, {}, {"alice"}} {
		t.Run(fmt.Sprintf("%#v", accounts), func(t *testing.T) {
			m, path := managedFixture(t, "")
			p := proposal("host")
			p.Accounts = accounts
			h, err := m.Enroll(t.Context(), p, "")
			require.NoError(t, err)
			_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Revision, nil)
			require.NoError(t, err)
			require.NoError(t, m.Close())
			fresh, err := Open(path)
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
	approved, err := m.Enroll(t.Context(), proposal("taken"), "")
	require.NoError(t, err)
	approved, err = m.Change(t.Context(), "admin", "approve", approved.ID, approved.Revision, nil)
	require.NoError(t, err)
	pending, err := m.Enroll(t.Context(), proposal("taken"), "")
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Status)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)

	// Editing the existing record can release the name for the pending request.
	moved := proposal("moved")
	_, err = m.Change(t.Context(), "admin", "edit", approved.ID, approved.Revision, &moved)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Revision, nil)
	require.NoError(t, err)

	pending, err = m.Enroll(t.Context(), proposal("static"), "")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Revision, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)
	current, _, err := m.LookupHost(t.Context(), "static")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, current.Policy.Accounts)

	// Editing the pending request can resolve a conflict with a active record.
	moved = proposal("free")
	pending, err = m.Change(t.Context(), "admin", "edit", pending.ID, pending.Revision, &moved)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Revision, nil)
	require.NoError(t, err)
}

func TestUnapprovedRecordsNeverAffectResolution(t *testing.T) {
	for _, action := range []string{"pending", "deny", "remove", "deny-then-remove"} {
		t.Run(action, func(t *testing.T) {
			m, path := managedFixture(t, "hosts:\n - pattern: '*.example'\n   accounts: [root]\n")
			accepted, err := m.Enroll(t.Context(), proposal("accepted.example"), "")
			require.NoError(t, err)
			_, err = m.Change(t.Context(), "admin", "approve", accepted.ID, accepted.Revision, nil)
			require.NoError(t, err)

			pending, err := m.Enroll(t.Context(), proposal("old.example"), "")
			require.NoError(t, err)
			edited := proposal("new.example")
			edited.Names = append(edited.Names, "accepted.example")
			pending, err = m.Change(t.Context(), "admin", "edit", pending.ID, pending.Revision, &edited)
			require.NoError(t, err)
			if action == "deny" || action == "deny-then-remove" {
				pending, err = m.Change(t.Context(), "admin", "deny", pending.ID, pending.Revision, nil)
				require.NoError(t, err)
			}
			if action == "remove" || action == "deny-then-remove" {
				_, err = m.Change(t.Context(), "admin", "remove", pending.ID, pending.Revision, nil)
				require.NoError(t, err)
			}
			check := func(store *Store) {
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
			restarted, err := Open(path)
			require.NoError(t, err)
			defer restarted.Close()
			check(restarted)
		})
	}
}
