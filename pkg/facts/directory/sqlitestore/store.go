// Package sqlitestore implements the managed directory using embedded SQLite.
// All SQL and transaction ownership stay here; callers use directory.Store.
package sqlitestore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/storage"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

type Store struct{ db *sql.DB }

var _ directory.Store = (*Store)(nil)
var _ directory.Directory = (*Store)(nil)

func (s *Store) SupportsVersioning() bool { return true }

// Partial updates are not implemented yet.
func (s *Store) SupportsPatchUser() bool  { return false }
func (s *Store) SupportsPatchGroup() bool { return false }

// Open creates a private database if needed. Schema version mismatches fail
// startup; existing databases are never upgraded here. Opening a database never
// falls back to an empty in-memory directory.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("directory database path is required")
	}
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
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
	if version != 0 && version != 4 {
		return fmt.Errorf("unsupported directory database version %d", version)
	}
	if version == 0 {
		_, err = tx.Exec(`
CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), instance TEXT NOT NULL, revision INTEGER NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, user_name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE, external_id TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), user_type TEXT NOT NULL, department TEXT NOT NULL, organization TEXT NOT NULL, version INTEGER NOT NULL, created TEXT NOT NULL, modified TEXT NOT NULL);
CREATE TABLE groups (id TEXT PRIMARY KEY, external_id TEXT NOT NULL, display_name TEXT NOT NULL, version INTEGER NOT NULL, created TEXT NOT NULL, modified TEXT NOT NULL);
CREATE TABLE members (group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(group_id,user_id));
CREATE INDEX user_memberships ON members(user_id);
CREATE TABLE audit (time TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, resource_id TEXT NOT NULL, alias TEXT NOT NULL, previous_id TEXT NOT NULL);
PRAGMA user_version=4;`)
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
func audit(ctx context.Context, tx *sql.Tx, event directory.AuditEvent) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit (time,actor,action,resource_id,alias,previous_id) VALUES (?,?,?,?,?,?)", event.Time.Format(time.RFC3339Nano), event.Actor, event.Action, event.ID, event.Alias, event.PreviousID)
	return err
}

// scanMetadata reads the common revision and timestamp columns. Identity and
// membership are read by their own user/group operations below.
func scanMetadata(row *sql.Row, m *directory.Metadata, fields ...any) error {
	var created, modified string
	var version uint64
	fields = append(fields, &version, &created, &modified)
	if err := row.Scan(fields...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return directory.ErrNotFound
		}
		return err
	}
	m.Version = strconv.FormatUint(version, 10)
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

func readGroup(ctx context.Context, tx *sql.Tx, id string) (directory.ManagedGroup, error) {
	g := directory.ManagedGroup{Metadata: directory.Metadata{ID: id}, MemberIDs: []string{}}
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

func precondition(m directory.Metadata, expectedVersion string) error {
	if expectedVersion != "" && expectedVersion != m.Version {
		return directory.ErrVersion
	}
	return nil
}

func (s *Store) GetUser(ctx context.Context, id string) (*directory.ManagedUser, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	u, err := readUser(ctx, tx, id)
	if errors.Is(err, directory.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetGroup(ctx context.Context, id string) (*directory.ManagedGroup, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	g, err := readGroup(ctx, tx, id)
	if errors.Is(err, directory.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &g, nil
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

func (s *Store) ListGroups(ctx context.Context, start, count int) ([]directory.ManagedGroup, int, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	ids, total, err := listIDs(ctx, tx, "groups", start, count)
	if err != nil {
		return nil, 0, err
	}
	groups := make([]directory.ManagedGroup, 0, len(ids))
	for _, id := range ids {
		g, err := readGroup(ctx, tx, id)
		if err != nil {
			return nil, 0, err
		}
		groups = append(groups, g)
	}
	return groups, total, tx.Commit()
}

func (s *Store) CreateUser(ctx context.Context, user directory.ManagedUser, event directory.AuditEvent) (directory.ManagedUser, error) {
	return s.writeUser(ctx, "", user, "", event)
}
func (s *Store) ReplaceUser(ctx context.Context, user directory.ManagedUser, expectedVersion string, event directory.AuditEvent) (directory.ManagedUser, error) {
	if user.ID == "" {
		return directory.ManagedUser{}, directory.ErrNotFound
	}
	return s.writeUser(ctx, user.ID, user, expectedVersion, event)
}

func (s *Store) writeUser(ctx context.Context, id string, user directory.ManagedUser, expectedVersion string, event directory.AuditEvent) (directory.ManagedUser, error) {
	create := id == ""
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return directory.ManagedUser{}, err
	}
	defer tx.Rollback()
	m := directory.Metadata{ID: id}
	if create {
		m.ID = user.ID
		m.Created = user.Created
		if err := unusedID(ctx, tx, m.ID); err != nil {
			return directory.ManagedUser{}, err
		}
	} else {
		old, err := readUser(ctx, tx, id)
		if err != nil {
			return directory.ManagedUser{}, err
		}
		if err = precondition(old.Metadata, expectedVersion); err != nil {
			return directory.ManagedUser{}, err
		}
		m = old.Metadata
	}
	var other string
	// The comparison key belongs to the SQLite index, not the user record.
	nameKey := cases.Fold().String(norm.NFKC.String(user.UserName))
	err = tx.QueryRowContext(ctx, "SELECT id FROM users WHERE id<>? AND name_key=? LIMIT 1", m.ID, nameKey).Scan(&other)
	if err == nil {
		return directory.ManagedUser{}, directory.ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return directory.ManagedUser{}, err
	}
	m.Modified = user.Modified
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
	if err = audit(ctx, tx, event); err != nil {
		return directory.ManagedUser{}, err
	}
	return user, tx.Commit()
}

func (s *Store) CreateGroup(ctx context.Context, group directory.ManagedGroup, event directory.AuditEvent) (directory.ManagedGroup, error) {
	return s.writeGroup(ctx, "", group, "", event)
}
func (s *Store) ReplaceGroup(ctx context.Context, group directory.ManagedGroup, expectedVersion string, event directory.AuditEvent) (directory.ManagedGroup, error) {
	if group.ID == "" {
		return directory.ManagedGroup{}, directory.ErrNotFound
	}
	return s.writeGroup(ctx, group.ID, group, expectedVersion, event)
}

// writeGroup owns a group and its direct membership replacement.
// Display names need not be unique; resource IDs distinguish the groups.
func (s *Store) writeGroup(ctx context.Context, id string, group directory.ManagedGroup, expectedVersion string, event directory.AuditEvent) (directory.ManagedGroup, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return directory.ManagedGroup{}, err
	}
	defer tx.Rollback()
	m := directory.Metadata{ID: group.ID, Created: group.Created}
	if id == "" {
		if err := unusedID(ctx, tx, m.ID); err != nil {
			return directory.ManagedGroup{}, err
		}
	} else {
		old, err := readGroup(ctx, tx, id)
		if err != nil {
			return directory.ManagedGroup{}, err
		}
		if err = precondition(old.Metadata, expectedVersion); err != nil {
			return directory.ManagedGroup{}, err
		}
		m = old.Metadata
	}
	for _, userID := range group.MemberIDs {
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=?)", userID).Scan(&exists); err != nil {
			return directory.ManagedGroup{}, err
		}
		if !exists {
			return directory.ManagedGroup{}, fmt.Errorf("%w: member must reference an existing user", directory.ErrInvalid)
		}
	}
	m.Modified = group.Modified
	m, err = changed(ctx, tx, m)
	if err != nil {
		return directory.ManagedGroup{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO groups (id,external_id,display_name,version,created,modified) VALUES (?,?,?,?,?,?)
 ON CONFLICT(id) DO UPDATE SET external_id=excluded.external_id,display_name=excluded.display_name,version=excluded.version,modified=excluded.modified`, m.ID, group.ExternalID, group.DisplayName, m.Version, m.Created.Format(time.RFC3339Nano), m.Modified.Format(time.RFC3339Nano))
	if err != nil {
		return directory.ManagedGroup{}, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM members WHERE group_id=?", m.ID); err != nil {
		return directory.ManagedGroup{}, err
	}
	for _, userID := range group.MemberIDs {
		_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO members (group_id,user_id) VALUES (?,?)", m.ID, userID)
		if err != nil {
			return directory.ManagedGroup{}, err
		}
	}
	if err = audit(ctx, tx, event); err != nil {
		return directory.ManagedGroup{}, err
	}
	// Return the persisted membership set, including deduplication and ordering.
	out, err := readGroup(ctx, tx, m.ID)
	if err != nil {
		return directory.ManagedGroup{}, err
	}
	return out, tx.Commit()
}

// unusedID checks the shared resource namespace within the mutation transaction.
func unusedID(ctx context.Context, tx *sql.Tx, id string) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=? UNION ALL SELECT 1 FROM groups WHERE id=?)", id, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return directory.ErrConflict
	}
	return nil
}

// changed assigns the storage-owned version within the mutation transaction.
func changed(ctx context.Context, tx *sql.Tx, m directory.Metadata) (directory.Metadata, error) {
	version, err := next(ctx, tx)
	m.Version = strconv.FormatUint(version, 10)
	return m, err
}

func (s *Store) DeleteUser(ctx context.Context, id, expectedVersion string, modified time.Time, event directory.AuditEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	u, err := readUser(ctx, tx, id)
	if err != nil {
		return err
	}
	if err = precondition(u.Metadata, expectedVersion); err != nil {
		return err
	}
	n, err := next(ctx, tx)
	if err != nil {
		return err
	}
	// Membership deletion changes each affected group's version in the same commit.
	_, err = tx.ExecContext(ctx, "UPDATE groups SET version=?,modified=? WHERE id IN (SELECT group_id FROM members WHERE user_id=?)", n, modified.Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM users WHERE id=?", id); err != nil {
		return err
	}
	if err = audit(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteGroup(ctx context.Context, id, expectedVersion string, event directory.AuditEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := readGroup(ctx, tx, id)
	if err != nil {
		return err
	}
	if err = precondition(g.Metadata, expectedVersion); err != nil {
		return err
	}
	// Memberships are removed by the foreign-key cascade. Names are not reserved.
	if _, err = tx.ExecContext(ctx, "DELETE FROM groups WHERE id=?", id); err != nil {
		return err
	}
	if err = audit(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

// LookupUser reads one authentication identity and its current group facts from
// one SQLite read transaction.
func (s *Store) LookupUser(ctx context.Context, id string) (*directory.User, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	query := `SELECT u.id,u.user_name,u.active,u.user_type,u.department,u.organization,g.id,g.display_name,g.external_id
FROM users u LEFT JOIN members m ON m.user_id=u.id LEFT JOIN groups g ON g.id=m.group_id`
	query += " WHERE u.id=?"
	query += " ORDER BY g.display_name,g.id"
	rows, err := tx.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var user *directory.User
	for rows.Next() {
		var u directory.User
		var groupID, groupName, groupExternalID sql.NullString
		if err = rows.Scan(&u.ID, &u.UserName, &u.Active, &u.UserType, &u.Department, &u.Organization, &groupID, &groupName, &groupExternalID); err != nil {
			return nil, err
		}
		if user == nil {
			u.Groups = []directory.Group{}
			user = &u
		}
		if groupID.Valid {
			g := directory.ManagedGroup{
				Metadata:    directory.Metadata{ID: groupID.String},
				DisplayName: groupName.String,
				ExternalID:  groupExternalID.String,
			}
			user.Groups = append(user.Groups, g.Group())
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return user, nil
}

// Audit uses SQLite row positions only to resume this backend's scan. They are
// not audit event fields or a cross-backend ordering guarantee.
func (s *Store) Audit(ctx context.Context, cursor string, limit int) ([]directory.AuditEvent, string, error) {
	if limit == 0 {
		limit = directory.DefaultAuditLimit
	}
	if limit < 0 || limit > directory.MaxAuditLimit {
		return nil, "", fmt.Errorf("%w: audit limit must be between 1 and %d", directory.ErrInvalid, directory.MaxAuditLimit)
	}
	var after int64
	if cursor != "" {
		var err error
		after, err = strconv.ParseInt(cursor, 10, 64)
		if err != nil || after < 0 {
			return nil, "", fmt.Errorf("%w: invalid audit cursor", directory.ErrInvalid)
		}
	}
	rows, err := s.db.QueryContext(ctx, "SELECT rowid,time,actor,action,resource_id,alias,previous_id FROM audit WHERE rowid>? ORDER BY rowid LIMIT ?", after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	events := []directory.AuditEvent{}
	var last int64
	for rows.Next() {
		if len(events) == limit {
			return events, strconv.FormatInt(last, 10), nil
		}
		var e directory.AuditEvent
		var stamp string
		if err = rows.Scan(&last, &stamp, &e.Actor, &e.Action, &e.ID, &e.Alias, &e.PreviousID); err != nil {
			return nil, "", err
		}
		if e.Time, err = time.Parse(time.RFC3339Nano, stamp); err != nil {
			return nil, "", err
		}
		events = append(events, e)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	return events, "", nil
}
