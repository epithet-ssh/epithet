package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func readItem(t *testing.T, m *Managed, id string) *itemRecord {
	t.Helper()
	data, err := os.ReadFile(m.files.itemPath(id))
	require.NoError(t, err)
	var r itemRecord
	require.NoError(t, DecodeYAML(data, &r))
	return &r
}
func TestTokenFilenameBecomesHostAndOnlyThatFileChanges(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	token, value, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	require.Equal(t, value, token.ID)
	before := readItem(t, m, value)
	require.Equal(t, "token", before.Kind)
	require.Nil(t, before.Host)
	other, _, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	otherPath := m.files.itemPath(other.ID)
	otherInfo, err := os.Stat(otherPath)
	require.NoError(t, err)
	otherData, err := os.ReadFile(otherPath)
	require.NoError(t, err)

	h, err := m.Enroll(proposal("host.example"), value)
	require.NoError(t, err)
	require.Equal(t, value, h.ID)
	after := readItem(t, m, value)
	require.Equal(t, "host", after.Kind)
	require.Equal(t, value, after.Host.ID)
	require.Equal(t, value, after.Token.UsedBy)
	require.Len(t, after.Audit, 2)
	updatedInfo, err := os.Stat(otherPath)
	require.NoError(t, err)
	require.True(t, os.SameFile(otherInfo, updatedInfo), "another item must not even be replaced")
	updatedData, err := os.ReadFile(otherPath)
	require.NoError(t, err)
	require.Equal(t, otherData, updatedData)
	entries, err := os.ReadDir(m.files.dir)
	require.NoError(t, err)
	require.Len(t, entries, 2, "redemption must not create a second item")
	require.NoError(t, m.Close())
	restarted, err := OpenManaged(m.files.root, m.static)
	require.NoError(t, err)
	defer restarted.Close()
	_, err = restarted.Enroll(proposal("ignored"), value)
	require.ErrorIs(t, err, ErrToken)
	_, err = restarted.Enroll(proposal("second"), value)
	require.ErrorIs(t, err, ErrToken)
}
func TestHostnameLookupUsesIndexesWithoutFilesystemReads(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - pattern: '*'\n   accounts: [root]\n")
	h, err := m.Enroll(proposal("host"), "")
	require.NoError(t, err)
	h, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	// Move the entire directory out of the way. A resolver which touched any
	// record on disk would fail; committed in-memory lookup remains available.
	require.NoError(t, os.Rename(m.files.dir, m.files.dir+".offline"))
	got, _, err := m.LookupHostSnapshot(t.Context(), "HOST")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, got.Policy.Accounts)
	missing, err := m.LookupHost(t.Context(), "fallback")
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, missing.Policy.Accounts)
	require.NoError(t, os.Rename(m.files.dir+".offline", m.files.dir))
}
func TestRestartRebuildsNamesAndKeepsRetiredClaims(t *testing.T) {
	m, _ := managedFixture(t, "hosts:\n - pattern: '*'\n   accounts: [root]\n")
	h, err := m.Enroll(proposal("old"), "")
	require.NoError(t, err)
	h, err = m.Change("admin", "approve", h.ID, h.Revision, nil)
	require.NoError(t, err)
	p := proposal("current")
	h, err = m.Change("admin", "edit", h.ID, h.Revision, &p)
	require.NoError(t, err)
	r := readItem(t, m, h.ID)
	require.Contains(t, r.Host.RetiredNames, "old")
	_, oldRevision, err := m.LookupHostSnapshot(t.Context(), "current")
	require.NoError(t, err)
	require.NoError(t, m.Close())
	// Offline emergency edit: name the host differently and explicitly retain
	// its previous name. No index file exists to update or repair.
	r.Host.Proposal.Names = []string{"offline-name"}
	r.Host.RetiredNames = append(r.Host.RetiredNames, "current")
	data, err := yaml.Marshal(r)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(m.files.itemPath(h.ID), data, 0600))
	restarted, err := OpenManaged(m.files.root, m.static)
	require.NoError(t, err)
	defer restarted.Close()
	got, newRevision, err := restarted.LookupHostSnapshot(t.Context(), "offline-name")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotEqual(t, oldRevision, newRevision)
	for _, name := range []string{"old", "current"} {
		got, err := restarted.LookupHost(t.Context(), name)
		require.NoError(t, err)
		require.Nil(t, got)
	}
	require.NoError(t, restarted.Close())
	again, err := OpenManaged(m.files.root, m.static)
	require.NoError(t, err)
	defer again.Close()
	_, stable, err := again.LookupHostSnapshot(t.Context(), "offline-name")
	require.NoError(t, err)
	require.Equal(t, newRevision, stable)
}
func TestRebuildRejectsConflictingApprovedItems(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	a, err := m.Enroll(proposal("same"), "")
	require.NoError(t, err)
	b, err := m.Enroll(proposal("same"), "")
	require.NoError(t, err)
	_, err = m.Change("admin", "approve", a.ID, a.Revision, nil)
	require.NoError(t, err)
	r := readItem(t, m, b.ID)
	r.Host.Status = "approved"
	require.NoError(t, m.Close())
	data, err := yaml.Marshal(r)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(m.files.itemPath(b.ID), data, 0600))
	_, err = OpenManaged(m.files.root, m.static)
	require.ErrorIs(t, err, ErrConflict)
	require.ErrorContains(t, err, "same")
	require.ErrorContains(t, err, a.ID)
	require.ErrorContains(t, err, b.ID)
}
func TestExclusiveItemCreationDoesNotOverwriteCollision(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	occupied := strings.Repeat("a", 64)
	next := strings.Repeat("b", 64)
	r := &itemRecord{Version: 2, Kind: "token", Token: &EnrollmentToken{ID: occupied, ExpiresAt: time.Now().Add(time.Hour)}}
	require.NoError(t, m.files.write(r, true)) // simulate a filename collision unknown to the index
	original, err := os.ReadFile(m.files.itemPath(occupied))
	require.NoError(t, err)
	calls := 0
	m.files.newID = func() (string, error) {
		calls++
		if calls == 1 {
			return occupied, nil
		}
		return next, nil
	}
	token, value, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	require.Equal(t, next, value)
	require.Equal(t, next, token.ID)
	require.Equal(t, 2, calls)
	after, err := os.ReadFile(m.files.itemPath(occupied))
	require.NoError(t, err)
	require.Equal(t, original, after)
	require.NoError(t, m.Health())
}
func TestRedemptionFailureLeavesTokenOrHostNeverBoth(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-replace", true: "after-replace"}[published], func(t *testing.T) {
			m, _ := managedFixture(t, "users: []\n")
			_, value, err := m.CreateToken("admin", time.Hour)
			require.NoError(t, err)
			realWrite := m.files.writeAtomic
			m.files.writeAtomic = func(path string, data []byte, create bool) error {
				if published {
					if err := realWrite(path, data, create); err != nil {
						return err
					}
				}
				return errors.New("simulated storage failure")
			}

			_, err = m.Enroll(proposal("host"), value)
			require.ErrorIs(t, err, ErrStorage)
			_, err = m.LookupHost(t.Context(), "host")
			require.ErrorIs(t, err, ErrStorage)
			require.NoError(t, m.Close())
			restarted, err := OpenManaged(m.files.root, m.static)
			require.NoError(t, err)
			defer restarted.Close()
			r := readItem(t, restarted, value)
			if published {
				require.Equal(t, "host", r.Kind)
			} else {
				require.Equal(t, "token", r.Kind)
			}
			if published {
				_, err = restarted.Enroll(proposal("retry"), value)
				require.ErrorIs(t, err, ErrToken)
			} else {
				host, err := restarted.Enroll(proposal("host"), value)
				require.NoError(t, err)
				require.Equal(t, value, host.ID)
			}
			_, err = restarted.Enroll(proposal("another"), value)
			require.ErrorIs(t, err, ErrToken)
		})
	}
}
func TestLegacySnapshotMigrationPreservesAdmissionAndRevokesTokens(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("a", 24)
	tokenID := strings.Repeat("b", 24)
	oldSecret := strings.Repeat("c", 64)
	old := legacyState{Version: 1, Hosts: []HostRecord{{ID: id, Revision: 3, Status: "approved", Proposal: proposal("migrated"), CreatedAt: time.Now(), UpdatedAt: time.Now()}}, Tokens: []legacyToken{{EnrollmentToken: EnrollmentToken{ID: tokenID, ExpiresAt: time.Now().Add(time.Hour)}, Hash: digest(oldSecret)}}, BlockedNames: []string{"retired"}, Audit: []AuditEvent{{At: time.Now(), Actor: "admin", Action: "approve", Resource: id}}}
	data, err := yaml.Marshal(old)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "inventory.yaml"), data, 0600))
	m, err := OpenManaged(dir, nil)
	require.NoError(t, err)
	defer m.Close()
	require.FileExists(t, filepath.Join(dir, "inventory.v1.yaml.bak"))
	require.NoFileExists(t, filepath.Join(dir, "inventory.yaml"))
	require.FileExists(t, m.files.itemPath(id))
	host, err := m.LookupHost(t.Context(), "migrated")
	require.NoError(t, err)
	require.NotNil(t, host)
	require.Contains(t, m.names, "retired")
	tokens, err := m.Tokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	require.True(t, tokens[0].Revoked)
	_, err = m.Enroll(proposal("other"), oldSecret)
	require.ErrorIs(t, err, ErrToken)
	audit, err := m.Audit()
	require.NoError(t, err)
	require.Len(t, audit, 1)
	require.Equal(t, id, audit[0].Resource)
	_, err = m.Change("admin", "remove", id, 3, nil)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	// Simulate a crash after linking the backup but before unlinking the old
	// snapshot. Restart must finish archival without resurrecting its approval.
	require.NoError(t, os.Link(filepath.Join(dir, "inventory.v1.yaml.bak"), filepath.Join(dir, "inventory.yaml")))
	restarted, err := OpenManaged(dir, nil)
	require.NoError(t, err)
	require.NoFileExists(t, filepath.Join(dir, "inventory.yaml"))
	host, err = restarted.LookupHost(t.Context(), "migrated")
	require.NoError(t, err)
	require.Nil(t, host)
	backup, err := os.ReadFile(filepath.Join(dir, "inventory.v1.yaml.bak"))
	require.NoError(t, err)
	require.Equal(t, data, backup)
	// A backup can never silently restore an old approval if records go missing.
	require.NoError(t, restarted.Close())
	require.NoError(t, os.Rename(m.files.dir, m.files.dir+".offline"))
	_, err = OpenManaged(dir, nil)
	require.ErrorContains(t, err, "records directory is missing")
}
func TestItemRejectsFilenameMismatchAndTraversal(t *testing.T) {
	m, _ := managedFixture(t, "users: []\n")
	_, err := m.Enroll(proposal("x"), "../inventory.lock")
	require.ErrorIs(t, err, ErrToken)
	_, value, err := m.CreateToken("admin", time.Hour)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	require.NoError(t, os.Rename(m.files.itemPath(value), m.files.itemPath(strings.Repeat("a", 64))))
	_, err = OpenManaged(m.files.root, nil)
	require.ErrorContains(t, err, "record ID must match its filename")
}
