// Package sqlitestore implements the managed directory using embedded SQLite.
// All SQL and transaction ownership stay here; callers use directory.Store.
package sqlitestore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

var _ directory.Store = (*Store)(nil)

// Open creates a private database if needed. Schema version mismatches fail
// startup; opening a database never falls back to an empty in-memory directory.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("directory database path is required")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		err = f.Close()
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{"_pragma": {"foreign_keys(1)", "busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)"}, "_txlock": {"immediate"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	// One connection serializes local mutations without leaking locks to callers.
	// SQLite transactions also protect against other processes using the same DB.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err = s.initialize(); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening directory: %w", err)
	}
	return s, nil
}

func (s *Store) initialize() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != 0 && version != 1 {
		return fmt.Errorf("unsupported directory database version %d", version)
	}
	if version == 0 {
		_, err = tx.Exec(`
CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), instance TEXT NOT NULL, revision INTEGER NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, user_name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE, external_id TEXT NOT NULL UNIQUE, active INTEGER NOT NULL CHECK(active IN (0,1)), user_type TEXT NOT NULL, department TEXT NOT NULL, organization TEXT NOT NULL, version INTEGER NOT NULL, created TEXT NOT NULL, modified TEXT NOT NULL);
CREATE TABLE groups (id TEXT PRIMARY KEY, external_id TEXT NOT NULL, display_name TEXT NOT NULL, version INTEGER NOT NULL, created TEXT NOT NULL, modified TEXT NOT NULL);
CREATE TABLE members (group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(group_id,user_id));
CREATE INDEX user_memberships ON members(user_id);
CREATE TABLE aliases (name TEXT PRIMARY KEY, group_id TEXT NOT NULL UNIQUE);
CREATE TABLE audit (sequence INTEGER PRIMARY KEY, revision INTEGER NOT NULL, time TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, resource_id TEXT NOT NULL, alias TEXT NOT NULL, previous_id TEXT NOT NULL);
PRAGMA user_version=1;`)
		if err != nil {
			return err
		}
		if _, err = tx.Exec("INSERT INTO state VALUES (1, ?, 0)", rand.Text()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Close() error { return s.db.Close() }
func revision(ctx context.Context, tx *sql.Tx) (uint64, string, error) {
	var n uint64
	var instance string
	err := tx.QueryRowContext(ctx, "SELECT revision, instance FROM state WHERE singleton=1").Scan(&n, &instance)
	return n, instance, err
}
func next(ctx context.Context, tx *sql.Tx) (uint64, error) {
	if _, err := tx.ExecContext(ctx, "UPDATE state SET revision=revision+1 WHERE singleton=1"); err != nil {
		return 0, err
	}
	n, _, err := revision(ctx, tx)
	return n, err
}
func audit(ctx context.Context, tx *sql.Tx, n uint64, actor, action, id, alias, previous string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit (revision,time,actor,action,resource_id,alias,previous_id) VALUES (?,?,?,?,?,?,?)", n, time.Now().UTC().Format(time.RFC3339Nano), actor, action, id, alias, previous)
	return err
}

// scanMetadata reads the common revision and timestamp columns. Identity and
// membership are read by their own user/group operations below.
func scanMetadata(row *sql.Row, m *directory.Metadata, fields ...any) error {
	var created, modified string
	fields = append(fields, &m.Version, &created, &modified)
	if err := row.Scan(fields...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return directory.ErrNotFound
		}
		return err
	}
	var err error
	if m.Created, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return err
	}
	m.Modified, err = time.Parse(time.RFC3339Nano, modified)
	return err
}

func readUser(ctx context.Context, tx *sql.Tx, id string) (directory.ManagedUser, error) {
	u := directory.ManagedUser{Metadata: directory.Metadata{ID: id}}
	err := scanMetadata(tx.QueryRowContext(ctx, "SELECT external_id,user_name,active,user_type,department,organization,version,created,modified FROM users WHERE id=?", id), &u.Metadata, &u.ExternalID, &u.UserName, &u.Active, &u.UserType, &u.Department, &u.Organization)
	return u, err
}

func readGroup(ctx context.Context, tx *sql.Tx, id string) (directory.Group, error) {
	g := directory.Group{Metadata: directory.Metadata{ID: id}, MemberIDs: []string{}}
	err := scanMetadata(tx.QueryRowContext(ctx, "SELECT external_id,display_name,version,created,modified FROM groups WHERE id=?", id), &g.Metadata, &g.ExternalID, &g.DisplayName)
	if err != nil {
		return g, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT user_id FROM members WHERE group_id=? ORDER BY user_id", id)
	if err != nil {
		return g, err
	}
	defer rows.Close()
	for rows.Next() {
		var userID string
		if err = rows.Scan(&userID); err != nil {
			return g, err
		}
		g.MemberIDs = append(g.MemberIDs, userID)
	}
	return g, rows.Err()
}

func precondition(m directory.Metadata, match string) error {
	if match == "" || match == "*" {
		return nil
	}
	for _, tag := range strings.Split(match, ",") {
		if strings.TrimSpace(tag) == m.ETag() {
			return nil
		}
	}
	return directory.ErrVersion
}

func (s *Store) GetUser(ctx context.Context, id string) (directory.ManagedUser, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return directory.ManagedUser{}, err
	}
	defer tx.Rollback()
	u, err := readUser(ctx, tx, id)
	if err != nil {
		return u, err
	}
	return u, tx.Commit()
}

func (s *Store) GetGroup(ctx context.Context, id string) (directory.Group, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return directory.Group{}, err
	}
	defer tx.Rollback()
	g, err := readGroup(ctx, tx, id)
	if err != nil {
		return g, err
	}
	return g, tx.Commit()
}

// listIDs keeps count and selection in the caller's transaction. Table is an
// internal SQL identifier supplied only by ListUsers and ListGroups.
func listIDs(ctx context.Context, tx *sql.Tx, table string, start, count int) ([]string, int, error) {
	if start < 1 || count < 0 {
		return nil, 0, fmt.Errorf("invalid directory query")
	}
	var total int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM "+table+" ORDER BY id LIMIT ? OFFSET ?", count, start-1)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, 0, err
		}
		ids = append(ids, id)
	}
	return ids, total, rows.Err()
}

func (s *Store) ListUsers(ctx context.Context, start, count int) ([]directory.ManagedUser, int, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	ids, total, err := listIDs(ctx, tx, "users", start, count)
	if err != nil {
		return nil, 0, err
	}
	users := make([]directory.ManagedUser, 0, len(ids))
	for _, id := range ids {
		u, err := readUser(ctx, tx, id)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, tx.Commit()
}

func (s *Store) ListGroups(ctx context.Context, start, count int) ([]directory.Group, int, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	ids, total, err := listIDs(ctx, tx, "groups", start, count)
	if err != nil {
		return nil, 0, err
	}
	groups := make([]directory.Group, 0, len(ids))
	for _, id := range ids {
		g, err := readGroup(ctx, tx, id)
		if err != nil {
			return nil, 0, err
		}
		groups = append(groups, g)
	}
	return groups, total, tx.Commit()
}

func (s *Store) CreateUser(ctx context.Context, user directory.ManagedUser) (directory.ManagedUser, error) {
	return s.writeUser(ctx, "", user, "")
}
func (s *Store) ReplaceUser(ctx context.Context, id string, user directory.ManagedUser, match string) (directory.ManagedUser, error) {
	if id == "" {
		return directory.ManagedUser{}, directory.ErrNotFound
	}
	return s.writeUser(ctx, id, user, match)
}

func (s *Store) writeUser(ctx context.Context, id string, user directory.ManagedUser, match string) (directory.ManagedUser, error) {
	if strings.TrimSpace(user.UserName) == "" || strings.TrimSpace(user.ExternalID) == "" {
		return directory.ManagedUser{}, fmt.Errorf("%w: userName and externalId are required", directory.ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return directory.ManagedUser{}, err
	}
	defer tx.Rollback()
	m := directory.Metadata{ID: id}
	if id != "" {
		old, err := readUser(ctx, tx, id)
		if err != nil {
			return directory.ManagedUser{}, err
		}
		if err = precondition(old.Metadata, match); err != nil {
			return directory.ManagedUser{}, err
		}
		m = old.Metadata
	}
	nameKey := cases.Fold().String(norm.NFKC.String(user.UserName))
	var other string
	err = tx.QueryRowContext(ctx, "SELECT id FROM users WHERE id<>? AND (external_id=? OR name_key=?) LIMIT 1", id, user.ExternalID, nameKey).Scan(&other)
	if err == nil {
		return directory.ManagedUser{}, directory.ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return directory.ManagedUser{}, err
	}
	m, err = changed(ctx, tx, m)
	if err != nil {
		return directory.ManagedUser{}, err
	}
	user.Metadata = m
	_, err = tx.ExecContext(ctx, `INSERT INTO users (id,user_name,name_key,external_id,active,user_type,department,organization,version,created,modified) VALUES (?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(id) DO UPDATE SET user_name=excluded.user_name,name_key=excluded.name_key,external_id=excluded.external_id,active=excluded.active,user_type=excluded.user_type,department=excluded.department,organization=excluded.organization,version=excluded.version,modified=excluded.modified`, m.ID, user.UserName, nameKey, user.ExternalID, user.Active, user.UserType, user.Department, user.Organization, m.Version, m.Created.Format(time.RFC3339Nano), m.Modified.Format(time.RFC3339Nano))
	if err != nil {
		return directory.ManagedUser{}, err
	}
	if err = auditWrite(ctx, tx, m, id == ""); err != nil {
		return directory.ManagedUser{}, err
	}
	return user, tx.Commit()
}

func (s *Store) CreateGroup(ctx context.Context, group directory.Group) (directory.Group, error) {
	return s.writeGroup(ctx, "", group, "")
}
func (s *Store) ReplaceGroup(ctx context.Context, id string, group directory.Group, match string) (directory.Group, error) {
	if id == "" {
		return directory.Group{}, directory.ErrNotFound
	}
	return s.writeGroup(ctx, id, group, match)
}

// writeGroup owns membership replacement and the first claim of a policy alias.
// A display-name collision is an audited binding conflict, not a failed create.
func (s *Store) writeGroup(ctx context.Context, id string, group directory.Group, match string) (directory.Group, error) {
	if strings.TrimSpace(group.DisplayName) == "" {
		return directory.Group{}, fmt.Errorf("%w: displayName is required", directory.ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return directory.Group{}, err
	}
	defer tx.Rollback()
	m := directory.Metadata{ID: id}
	if id != "" {
		old, err := readGroup(ctx, tx, id)
		if err != nil {
			return directory.Group{}, err
		}
		if err = precondition(old.Metadata, match); err != nil {
			return directory.Group{}, err
		}
		m = old.Metadata
	}
	for _, userID := range group.MemberIDs {
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=?)", userID).Scan(&exists); err != nil {
			return directory.Group{}, err
		}
		if !exists {
			return directory.Group{}, fmt.Errorf("%w: member must reference an existing user", directory.ErrInvalid)
		}
	}
	m, err = changed(ctx, tx, m)
	if err != nil {
		return directory.Group{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO groups (id,external_id,display_name,version,created,modified) VALUES (?,?,?,?,?,?)
 ON CONFLICT(id) DO UPDATE SET external_id=excluded.external_id,display_name=excluded.display_name,version=excluded.version,modified=excluded.modified`, m.ID, group.ExternalID, group.DisplayName, m.Version, m.Created.Format(time.RFC3339Nano), m.Modified.Format(time.RFC3339Nano))
	if err != nil {
		return directory.Group{}, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM members WHERE group_id=?", m.ID); err != nil {
		return directory.Group{}, err
	}
	for _, userID := range group.MemberIDs {
		_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO members (group_id,user_id) VALUES (?,?)", m.ID, userID)
		if err != nil {
			return directory.Group{}, err
		}
	}
	if id == "" {
		var owner string
		err = tx.QueryRowContext(ctx, "SELECT group_id FROM aliases WHERE name=?", group.DisplayName).Scan(&owner)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.ExecContext(ctx, "INSERT INTO aliases VALUES (?,?)", group.DisplayName, m.ID)
			if err == nil {
				err = audit(ctx, tx, m.Version, "scim", "bind", m.ID, group.DisplayName, "")
			}
		case err == nil:
			err = audit(ctx, tx, m.Version, "scim", "name-conflict", m.ID, group.DisplayName, owner)
		}
		if err != nil {
			return directory.Group{}, err
		}
	}
	if err = auditWrite(ctx, tx, m, id == ""); err != nil {
		return directory.Group{}, err
	}
	// Return the persisted membership set, including deduplication and ordering.
	out, err := readGroup(ctx, tx, m.ID)
	if err != nil {
		return directory.Group{}, err
	}
	return out, tx.Commit()
}

// changed assigns storage-owned metadata within the mutation transaction.
func changed(ctx context.Context, tx *sql.Tx, m directory.Metadata) (directory.Metadata, error) {
	m.Modified = time.Now().UTC()
	if m.ID == "" {
		m.ID, m.Created = rand.Text(), m.Modified
	}
	var err error
	m.Version, err = next(ctx, tx)
	return m, err
}
func auditWrite(ctx context.Context, tx *sql.Tx, m directory.Metadata, create bool) error {
	action := "replace"
	if create {
		action = "create"
	}
	return audit(ctx, tx, m.Version, "scim", action, m.ID, "", "")
}

func (s *Store) DeleteUser(ctx context.Context, id, match string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	u, err := readUser(ctx, tx, id)
	if err != nil {
		return err
	}
	if err = precondition(u.Metadata, match); err != nil {
		return err
	}
	n, err := next(ctx, tx)
	if err != nil {
		return err
	}
	// Membership deletion changes each affected group's ETag in the same commit.
	_, err = tx.ExecContext(ctx, "UPDATE groups SET version=?,modified=? WHERE id IN (SELECT group_id FROM members WHERE user_id=?)", n, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM users WHERE id=?", id); err != nil {
		return err
	}
	if err = audit(ctx, tx, n, "scim", "delete", id, "", ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteGroup(ctx context.Context, id, match string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := readGroup(ctx, tx, id)
	if err != nil {
		return err
	}
	if err = precondition(g.Metadata, match); err != nil {
		return err
	}
	n, err := next(ctx, tx)
	if err != nil {
		return err
	}
	// Aliases intentionally survive deletion, reserving their policy names.
	if _, err = tx.ExecContext(ctx, "DELETE FROM groups WHERE id=?", id); err != nil {
		return err
	}
	if err = audit(ctx, tx, n, "scim", "delete", id, "", ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LookupUser(ctx context.Context, externalID string) (*directory.User, directory.Revision, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	n, instance, err := revision(ctx, tx)
	if err != nil {
		return nil, "", err
	}
	rev := directory.Revision(fmt.Sprintf("%s:%d", instance, n))
	var id string
	err = tx.QueryRowContext(ctx, "SELECT id FROM users WHERE external_id=?", externalID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, rev, tx.Commit()
	}
	if err != nil {
		return nil, "", err
	}
	stored, err := readUser(ctx, tx, id)
	if err != nil {
		return nil, "", err
	}
	u := directory.User{ID: stored.ExternalID, UserName: stored.UserName, UserType: stored.UserType, Active: stored.Active, Department: stored.Department, Organization: stored.Organization}
	u.Groups = []string{}
	rows, err := tx.QueryContext(ctx, "SELECT a.name FROM members m JOIN aliases a ON a.group_id=m.group_id WHERE m.user_id=? ORDER BY a.name", id)
	if err != nil {
		return nil, "", err
	}
	for rows.Next() {
		var alias string
		if err = rows.Scan(&alias); err != nil {
			rows.Close()
			return nil, "", err
		}
		u.Groups = append(u.Groups, alias)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	return &u, rev, tx.Commit()
}

func (s *Store) Bindings(ctx context.Context) (directory.BindingSnapshot, error) {
	out := directory.BindingSnapshot{Groups: []directory.GroupBinding{}}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	out.Revision, _, err = revision(ctx, tx)
	if err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT g.id,g.display_name,COALESCE(a.name,''), CASE WHEN a.name IS NOT NULL THEN 'bound' WHEN EXISTS(SELECT 1 FROM aliases WHERE name=g.display_name) THEN 'conflict' ELSE 'unbound' END
FROM groups g LEFT JOIN aliases a ON a.group_id=g.id
UNION ALL SELECT a.group_id,'',a.name,'deleted' FROM aliases a WHERE NOT EXISTS(SELECT 1 FROM groups g WHERE g.id=a.group_id)
ORDER BY 2,1`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var g directory.GroupBinding
		if err = rows.Scan(&g.ID, &g.DisplayName, &g.Alias, &g.Status); err != nil {
			rows.Close()
			return out, err
		}
		out.Groups = append(out.Groups, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Store) Rebind(ctx context.Context, actor, alias, id string, expected uint64, authorizationRevision directory.Revision) error {
	if actor == "" || strings.TrimSpace(alias) == "" {
		return fmt.Errorf("%w: actor and policy alias are required", directory.ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	n, instance, err := revision(ctx, tx)
	if err != nil {
		return err
	}
	if n != expected || authorizationRevision != directory.Revision(fmt.Sprintf("%s:%d", instance, n)) {
		return directory.ErrVersion
	}
	if _, err = readGroup(ctx, tx, id); err != nil {
		return err
	}
	var existing string
	err = tx.QueryRowContext(ctx, "SELECT name FROM aliases WHERE group_id=?", id).Scan(&existing)
	if err == nil && existing != alias {
		return fmt.Errorf("%w: group already has policy alias %q", directory.ErrConflict, existing)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT group_id FROM aliases WHERE name=?", alias).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if previous == id {
		return tx.Commit()
	}
	n, err = next(ctx, tx)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO aliases VALUES (?,?) ON CONFLICT(name) DO UPDATE SET group_id=excluded.group_id", alias, id); err != nil {
		return err
	}
	if err = audit(ctx, tx, n, actor, "rebind", id, alias, previous); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Audit(ctx context.Context, after directory.AuditSequence, limit int) ([]directory.AuditEvent, error) {
	if limit == 0 {
		limit = directory.DefaultAuditLimit
	}
	if limit < 0 || limit > directory.MaxAuditLimit {
		return nil, fmt.Errorf("%w: audit limit must be between 1 and %d", directory.ErrInvalid, directory.MaxAuditLimit)
	}
	out := []directory.AuditEvent{}
	rows, err := s.db.QueryContext(ctx, "SELECT sequence,revision,time,actor,action,resource_id,alias,previous_id FROM audit WHERE sequence>? ORDER BY sequence LIMIT ?", after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e directory.AuditEvent
		var stamp string
		if err = rows.Scan(&e.Sequence, &e.Revision, &stamp, &e.Actor, &e.Action, &e.ID, &e.Alias, &e.PreviousID); err != nil {
			return nil, err
		}
		if e.Time, err = time.Parse(time.RFC3339Nano, stamp); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
