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
	"github.com/epithet-ssh/epithet/pkg/principal"
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
			Labels        map[string]string       `yaml:"labels"`
			Accounts      []string                `yaml:"accounts"`
			PrincipalMode inventory.PrincipalMode `yaml:"principal-mode"`
			Realm         string                  `yaml:"realm"`
		} `yaml:"hosts"`
		Users []yaml.Node `yaml:"users"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(initialYAML), &initial))
	for _, h := range initial.Hosts {
		id := inventory.NewID()
		p := inventory.Host{Status: inventory.StatusActive, Names: h.Names, Labels: h.Labels, Accounts: h.Accounts, PrincipalMode: h.PrincipalMode.Effective(), Realm: principal.Realm(h.Realm)}
		p.ID = id
		_, err := m.UpsertHost(t.Context(), p, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id))
		require.NoError(t, err)
	}
	t.Cleanup(func() { m.Close() })
	return m, dbPath
}
func proposal(name string) inventory.Host {
	return inventory.Host{Names: []string{name}, Labels: map[string]string{}, Accounts: []string{"alice"}, PrincipalMode: inventory.AccountNamePrincipals}
}
func TestManagedAdmissionConflictAndWildcardFallback(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n  - names: ['*.example']\n    accounts: [root]\n")
	id2 := inventory.NewID()
	a, err := inventory.Enroll(t.Context(), m, id2, proposal("a.example"), "", inventory.NewAuditEvent("host", "enroll", id2))
	require.NoError(t, err)
	id3 := inventory.NewID()
	b, err := inventory.Enroll(t.Context(), m, id3, proposal("a.example"), "", inventory.NewAuditEvent("host", "enroll", id3))
	require.NoError(t, err)
	h, err := m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Accounts, "pending must not change wildcard admission")
	a, err = m.Change(t.Context(), "admin", "approve", a.ID, a.Version, nil)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", b.ID, b.Version, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)
	p := proposal("b.example")
	b, err = m.Change(t.Context(), "admin", "edit", b.ID, b.Version, &p)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", b.ID, b.Version, nil)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "remove", a.ID, a.Version, nil)
	require.NoError(t, err)
	h, err = m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, h.Accounts)
	id4 := inventory.NewID()
	a, err = inventory.Enroll(t.Context(), m, id4, proposal("a.example"), "", inventory.NewAuditEvent("host", "enroll", id4))
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", a.ID, a.Version, nil)
	require.NoError(t, err)
	h, err = m.LookupHost(context.Background(), "a.example")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, h.Accounts)
}
func TestManagedTokenAtomicSingleUseAndRestart(t *testing.T) {
	m, path := managedFixture(t, "")
	id5 := inventory.NewID()
	tok, err := m.CreateToken(t.Context(), id5, time.Hour, inventory.NewAuditEvent("admin", "token-create", id5))
	secret := tok.ID
	require.NoError(t, err)

	id6 := secret
	h, err := inventory.Enroll(t.Context(), m, id6, proposal("one"), secret, inventory.NewAuditEvent("host", "enroll", id6))
	require.NoError(t, err)
	require.Equal(t, "active", h.Status)
	id7 := secret
	_, err = inventory.Enroll(t.Context(), m, id7, proposal("different"), secret, inventory.NewAuditEvent("host", "enroll", id7))
	require.ErrorIs(t, err, inventory.ErrToken)
	id8 := secret
	_, err = inventory.Enroll(t.Context(), m, id8, proposal("two"), secret, inventory.NewAuditEvent("host", "enroll", id8))
	require.ErrorIs(t, err, inventory.ErrToken)
	require.Equal(t, secret, h.ID)
	require.Equal(t, tok.ID, h.ID)
	require.NoError(t, m.Close())
	fresh, err := Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	tokens, err := fresh.Tokens(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, tok.ID, tokens[0].ID)
	require.Equal(t, h.ID, tokens[0].UsedBy)
	host, err := fresh.LookupHost(context.Background(), "one")
	require.NoError(t, err)
	require.NotNil(t, host)
	_, err = fresh.Change(t.Context(), "admin", "remove", h.ID, h.Version, nil)
	require.NoError(t, err)
	require.NoError(t, fresh.Close())
	fresh, err = Open(path)
	require.NoError(t, err)
	defer fresh.Close()
	_, err = fresh.GetHost(t.Context(), h.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	tokens, err = fresh.Tokens(t.Context(), "", 0)
	require.NoError(t, err)
	require.Empty(t, tokens)
	host, err = fresh.LookupHost(t.Context(), "one")
	require.NoError(t, err)
	require.Nil(t, host)
	id9 := secret
	_, err = inventory.Enroll(t.Context(), fresh, id9, proposal("one"), secret, inventory.NewAuditEvent("host", "enroll", id9))
	require.ErrorIs(t, err, inventory.ErrToken, "deleted host must not make its token reusable")
	id10 := inventory.NewID()
	again, err := inventory.Enroll(t.Context(), fresh, id10, proposal("one"), "", inventory.NewAuditEvent("host", "enroll", id10))
	require.NoError(t, err)
	require.NotEqual(t, h.ID, again.ID)
	require.Equal(t, "pending", again.Status)
}
func TestManagedConcurrentApprovalAndRedemption(t *testing.T) {
	m, path := managedFixture(t, "")
	other, err := Open(path)
	require.NoError(t, err)
	defer other.Close()
	id11 := inventory.NewID()
	token, err := m.CreateToken(t.Context(), id11, time.Hour, inventory.NewAuditEvent("admin", "token-create", id11))
	secret := token.ID
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, n := range []string{"a", "b"} {
		store := []*Store{m, other}[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			id12 := secret
			_, e := inventory.Enroll(t.Context(), store, id12, proposal(n), secret, inventory.NewAuditEvent("host", "enroll", id12))
			results <- e
		}()
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
	id13 := inventory.NewID()
	a, e := inventory.Enroll(t.Context(), m, id13, proposal("same"), "", inventory.NewAuditEvent("host", "enroll", id13))
	require.NoError(t, e)
	id14 := inventory.NewID()
	b, e := inventory.Enroll(t.Context(), m, id14, proposal("same"), "", inventory.NewAuditEvent("host", "enroll", id14))
	require.NoError(t, e)
	results = make(chan error, 2)
	for i, h := range []*inventory.Host{a, b} {
		store := []*Store{m, other}[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := store.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
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
	m, _ := managedFixture(t, "hosts:\n - names: [static]\n   accounts: [root]\n - names: ['*']\n   accounts: [fallback]\n")
	id15 := inventory.NewID()
	pending, err := inventory.Enroll(t.Context(), m, id15, proposal("static"), "", inventory.NewAuditEvent("host", "enroll", id15))
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Version, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)
	id16 := inventory.NewID()
	h, err := inventory.Enroll(t.Context(), m, id16, proposal("dynamic"), "", inventory.NewAuditEvent("host", "enroll", id16))
	require.NoError(t, err)
	// A failed audit insert must roll back the approval and name changes.
	_, err = m.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END")
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
	require.ErrorIs(t, err, inventory.ErrStorage)
	current, err := m.GetHost(t.Context(), h.ID)
	require.NoError(t, err)
	require.Equal(t, h, current)
	_, err = m.db.Exec("DROP TRIGGER fail_audit")
	require.NoError(t, err)
	h, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	for _, name := range []string{"dynamic", "static", "fallback"} {
		_, err = m.LookupHost(context.Background(), name)
		require.ErrorIs(t, err, inventory.ErrStorage, "an unavailable database must not switch to a separate fallback")
	}
}
func TestManagedRevisionAndValidation(t *testing.T) {
	m, path := managedFixture(t, "")
	other, err := Open(path)
	require.NoError(t, err)
	defer other.Close()
	id17 := inventory.NewID()
	h, err := inventory.Enroll(t.Context(), m, id17, proposal("A.example"), "", inventory.NewAuditEvent("host", "enroll", id17))
	require.NoError(t, err)
	require.Equal(t, []string{"a.example"}, h.Names)
	p := proposal("other")
	_, err = m.Change(t.Context(), "admin", "edit", h.ID, h.Version, &p)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
	require.ErrorIs(t, err, inventory.ErrVersion)
	for _, body := range []string{"names: [a]\nprincipal-mode: account-name\n", "names: [a]\naccounts: []\nprincipal-mode: account-name\nstatus: active\n", "names: [a]\naccounts: []\nprincipal-mode: account-name\n---\n{}"} {
		_, err := inventory.ParseHost([]byte(body))
		require.Error(t, err)
	}
	p, err = inventory.ParseHost([]byte("names: [a]\naccounts: null\nprincipal-mode: account-name\n"))
	require.NoError(t, err)
	require.Nil(t, p.Accounts)
	p, err = inventory.ParseHost([]byte("names: [a]\naccounts: []\nprincipal-mode: account-name\n"))
	require.NoError(t, err)
	require.NotNil(t, p.Accounts)
}
func TestManagedTokenConflictDoesNotConsumeAndExpiry(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [taken]\n")
	id18 := inventory.NewID()
	token, err := m.CreateToken(t.Context(), id18, time.Hour, inventory.NewAuditEvent("admin", "token-create", id18))
	secret := token.ID
	require.NoError(t, err)
	id19 := secret
	_, err = inventory.Enroll(t.Context(), m, id19, proposal("taken"), secret, inventory.NewAuditEvent("host", "enroll", id19))
	require.ErrorIs(t, err, inventory.ErrConflict)
	id20 := secret
	_, err = inventory.Enroll(t.Context(), m, id20, proposal("free"), secret, inventory.NewAuditEvent("host", "enroll", id20))
	require.NoError(t, err)
	id21 := inventory.NewID()
	tok, err := m.CreateToken(t.Context(), id21, time.Hour, inventory.NewAuditEvent("admin", "token-create", id21))
	secret = tok.ID
	require.NoError(t, err)
	require.NoError(t, m.RevokeToken(t.Context(), tok.ID, inventory.NewAuditEvent("admin", "token-revoke", tok.ID)))
	id22 := secret
	_, err = inventory.Enroll(t.Context(), m, id22, proposal("revoked"), secret, inventory.NewAuditEvent("host", "enroll", id22))
	require.ErrorIs(t, err, inventory.ErrToken)
	id23 := inventory.NewID()
	expiredToken, err := m.CreateToken(t.Context(), id23, time.Nanosecond, inventory.NewAuditEvent("admin", "token-create", id23))
	secret = expiredToken.ID
	require.NoError(t, err)
	time.Sleep(time.Millisecond)
	id24 := secret
	_, err = inventory.Enroll(t.Context(), m, id24, proposal("expired"), secret, inventory.NewAuditEvent("host", "enroll", id24))
	require.ErrorIs(t, err, inventory.ErrToken)
}
func TestManagedRejectCorruptState(t *testing.T) {
	for _, initialYAML := range []string{"", "hosts:\n - names: [recovery]\n   accounts: [root]\n - names: ['*']\n"} {
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

	id25 := inventory.NewID()
	h, err := inventory.Enroll(t.Context(), m, id25, p, "", inventory.NewAuditEvent("host", "enroll", id25))
	require.NoError(t, err)
	p.Labels["role"] = "hijacked"
	h.Accounts[0] = "root"
	retry, err := m.GetHost(t.Context(), h.ID)
	require.NoError(t, err)
	retry.Labels["role"] = "hijacked"
	h, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
	require.NoError(t, err)
	host, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.Equal(t, "server", host.Labels["role"])
	require.Equal(t, []string{"alice"}, host.Accounts)
	host.Labels["role"] = "hijacked"
	next, err := m.LookupHost(t.Context(), "host")
	require.NoError(t, err)
	require.Equal(t, "server", next.Labels["role"])
}

func TestManagedSharedRealmsSurviveRestart(t *testing.T) {
	for _, realm := range []string{"fleet", "epithet-host-id-v1:" + strings.Repeat("A", 43)} {
		t.Run(realm, func(t *testing.T) {
			m, path := managedFixture(t, "")
			for i, name := range []string{"first", "second"} {
				p := proposal(name)
				p.PrincipalMode, p.Realm = inventory.EpithetPrincipalV1, principal.Realm(realm)
				p.Labels = map[string]string{"role": name}
				if i == 0 {
					p.Accounts = nil
				} else {
					p.Accounts = []string{}
				}
				id := inventory.NewID()
				h, err := inventory.Enroll(t.Context(), m, id, p, "", inventory.NewAuditEvent("host", "enroll", id))
				require.NoError(t, err)
				_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
				require.NoError(t, err)
			}
			require.NoError(t, m.Close())
			fresh, err := Open(path)
			require.NoError(t, err)
			defer fresh.Close()
			first, err := fresh.LookupHost(t.Context(), "first")
			require.NoError(t, err)
			second, err := fresh.LookupHost(t.Context(), "second")
			require.NoError(t, err)
			require.Equal(t, realm, string(first.Realm))
			require.Equal(t, first.Realm, second.Realm)
			require.Equal(t, "first", first.Labels["role"])
			require.Equal(t, "second", second.Labels["role"])
			require.Nil(t, first.Accounts)
			require.NotNil(t, second.Accounts)
			require.Empty(t, second.Accounts)
		})
	}
}

func TestManagedSharedRealmValidation(t *testing.T) {
	m, _ := managedFixture(t, "")
	p := proposal("host")
	p.Realm = "fleet"
	id33 := inventory.NewID()
	_, err := inventory.Enroll(t.Context(), m, id33, p, "", inventory.NewAuditEvent("host", "enroll", id33))
	require.ErrorContains(t, err, "requires epithet-principal-v1")
	p.PrincipalMode, p.Realm = inventory.EpithetPrincipalV1, "NewFleet"
	id34 := inventory.NewID()
	h, err := inventory.Enroll(t.Context(), m, id34, p, "", inventory.NewAuditEvent("host", "enroll", id34))
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
	require.NoError(t, err, "a named realm needs no separate declaration")
	p.Realm = "not a realm"
	id35 := inventory.NewID()
	_, err = inventory.Enroll(t.Context(), m, id35, p, "", inventory.NewAuditEvent("host", "enroll", id35))
	require.Error(t, err)
}

func TestManagedAccountSemanticsSurviveRestart(t *testing.T) {
	for _, accounts := range [][]string{nil, {}, {"alice"}} {
		t.Run(fmt.Sprintf("%#v", accounts), func(t *testing.T) {
			m, path := managedFixture(t, "")
			p := proposal("host")
			p.Accounts = accounts
			id36 := inventory.NewID()
			h, err := inventory.Enroll(t.Context(), m, id36, p, "", inventory.NewAuditEvent("host", "enroll", id36))
			require.NoError(t, err)
			_, err = m.Change(t.Context(), "admin", "approve", h.ID, h.Version, nil)
			require.NoError(t, err)
			require.NoError(t, m.Close())
			fresh, err := Open(path)
			require.NoError(t, err)
			defer fresh.Close()
			host, err := fresh.LookupHost(t.Context(), "host")
			require.NoError(t, err)
			require.Equal(t, accounts, host.Accounts)
		})
	}
}

func TestPendingConflictsAreResolvedBeforeApproval(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - names: [static]\n   accounts: [root]\n")
	id37 := inventory.NewID()
	approved, err := inventory.Enroll(t.Context(), m, id37, proposal("taken"), "", inventory.NewAuditEvent("host", "enroll", id37))
	require.NoError(t, err)
	approved, err = m.Change(t.Context(), "admin", "approve", approved.ID, approved.Version, nil)
	require.NoError(t, err)
	id38 := inventory.NewID()
	pending, err := inventory.Enroll(t.Context(), m, id38, proposal("taken"), "", inventory.NewAuditEvent("host", "enroll", id38))
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Status)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Version, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)

	// Editing the existing record can release the name for the pending request.
	moved := proposal("moved")
	_, err = m.Change(t.Context(), "admin", "edit", approved.ID, approved.Version, &moved)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Version, nil)
	require.NoError(t, err)

	id39 := inventory.NewID()
	pending, err = inventory.Enroll(t.Context(), m, id39, proposal("static"), "", inventory.NewAuditEvent("host", "enroll", id39))
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Version, nil)
	require.ErrorIs(t, err, inventory.ErrConflict)
	current, err := m.LookupHost(t.Context(), "static")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, current.Accounts)

	// Editing the pending request can resolve a conflict with a active record.
	moved = proposal("free")
	pending, err = m.Change(t.Context(), "admin", "edit", pending.ID, pending.Version, &moved)
	require.NoError(t, err)
	_, err = m.Change(t.Context(), "admin", "approve", pending.ID, pending.Version, nil)
	require.NoError(t, err)
}

func TestUnapprovedRecordsNeverAffectResolution(t *testing.T) {
	for _, action := range []string{"pending", "deny", "remove", "deny-then-remove"} {
		t.Run(action, func(t *testing.T) {
			m, path := managedFixture(t, "hosts:\n - names: ['*.example']\n   accounts: [root]\n")
			id40 := inventory.NewID()
			accepted, err := inventory.Enroll(t.Context(), m, id40, proposal("accepted.example"), "", inventory.NewAuditEvent("host", "enroll", id40))
			require.NoError(t, err)
			_, err = m.Change(t.Context(), "admin", "approve", accepted.ID, accepted.Version, nil)
			require.NoError(t, err)

			id41 := inventory.NewID()
			pending, err := inventory.Enroll(t.Context(), m, id41, proposal("old.example"), "", inventory.NewAuditEvent("host", "enroll", id41))
			require.NoError(t, err)
			edited := proposal("new.example")
			edited.Names = append(edited.Names, "accepted.example")
			pending, err = m.Change(t.Context(), "admin", "edit", pending.ID, pending.Version, &edited)
			require.NoError(t, err)
			if action == "deny" || action == "deny-then-remove" {
				pending, err = m.Change(t.Context(), "admin", "deny", pending.ID, pending.Version, nil)
				require.NoError(t, err)
			}
			if action == "remove" || action == "deny-then-remove" {
				_, err = m.Change(t.Context(), "admin", "remove", pending.ID, pending.Version, nil)
				require.NoError(t, err)
			}
			check := func(store *Store) {
				for _, name := range []string{"old.example", "new.example"} {
					h, err := store.LookupHost(t.Context(), name)
					require.NoError(t, err)
					require.NotNil(t, h)
					require.Equal(t, []string{"root"}, h.Accounts)
				}
				h, err := store.LookupHost(t.Context(), "accepted.example")
				require.NoError(t, err)
				require.Equal(t, []string{"alice"}, h.Accounts)
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
