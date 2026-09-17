// Package sqlitestore implements the managed directory using embedded SQLite.
// All SQL and transaction ownership stay here; callers use scim.Store.
package sqlitestore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/directory/scim"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

var _ scim.Store = (*Store)(nil)

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
CREATE TABLE resources (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('Users','Groups')), document BLOB NOT NULL, name TEXT NOT NULL, name_key TEXT NOT NULL, external_id TEXT, version INTEGER NOT NULL, created TEXT NOT NULL, modified TEXT NOT NULL);
CREATE UNIQUE INDEX user_external_id ON resources(external_id) WHERE kind='Users';
CREATE UNIQUE INDEX user_name ON resources(name_key) WHERE kind='Users';
CREATE TABLE members (group_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE, PRIMARY KEY(group_id,user_id));
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
func kindOK(k scim.Kind) bool { return k == scim.Users || k == scim.Groups }
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

func read(ctx context.Context, tx *sql.Tx, k scim.Kind, id string) (scim.Resource, error) {
	r := scim.Resource{ID: id, Kind: k}
	var data []byte
	var created, modified string
	err := tx.QueryRowContext(ctx, "SELECT document,version,created,modified FROM resources WHERE kind=? AND id=?", k, id).Scan(&data, &r.Version, &created, &modified)
	if errors.Is(err, sql.ErrNoRows) {
		return r, scim.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(data, &r.Document); err != nil {
		return r, err
	}
	if r.Created, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return r, err
	}
	r.Modified, err = time.Parse(time.RFC3339Nano, modified)
	return r, err
}
func precondition(r scim.Resource, match string) error {
	if match == "" || match == "*" {
		return nil
	}
	for _, tag := range strings.Split(match, ",") {
		if strings.TrimSpace(tag) == r.ETag() {
			return nil
		}
	}
	return scim.ErrVersion
}
func (s *Store) Get(ctx context.Context, k scim.Kind, id string) (scim.Resource, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return scim.Resource{}, err
	}
	defer tx.Rollback()
	r, err := read(ctx, tx, k, id)
	if err != nil {
		return r, err
	}
	return r, tx.Commit()
}
func (s *Store) List(ctx context.Context, k scim.Kind, start, count int) (scim.Page, error) {
	p := scim.Page{Resources: []scim.Resource{}}
	if !kindOK(k) || start < 1 || count < 0 {
		return p, fmt.Errorf("invalid directory query")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM resources WHERE kind=?", k).Scan(&p.Total); err != nil {
		return p, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM resources WHERE kind=? ORDER BY id LIMIT ? OFFSET ?", k, count, start-1)
	if err != nil {
		return p, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return p, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	for _, id := range ids {
		r, e := read(ctx, tx, k, id)
		if e != nil {
			return p, e
		}
		p.Resources = append(p.Resources, r)
	}
	return p, tx.Commit()
}
func (s *Store) Create(ctx context.Context, k scim.Kind, d scim.Document) (scim.Resource, error) {
	return s.write(ctx, k, "", d, "")
}
func (s *Store) Replace(ctx context.Context, k scim.Kind, id string, d scim.Document, match string) (scim.Resource, error) {
	if id == "" {
		return scim.Resource{}, scim.ErrNotFound
	}
	return s.write(ctx, k, id, d, match)
}

// write owns the entire resource transition, including first-claim aliases.
// A name collision is an audited binding conflict, never a failed SCIM create.
func (s *Store) write(ctx context.Context, k scim.Kind, id string, d scim.Document, match string) (scim.Resource, error) {
	var out scim.Resource
	if !kindOK(k) {
		return out, fmt.Errorf("%w: invalid resource kind", scim.ErrInvalid)
	}
	name := d.Text("displayName")
	if k == scim.Users {
		name = d.Text("userName")
	}
	external := d.Text("externalId")
	if name == "" || (k == scim.Users && external == "") {
		return out, fmt.Errorf("%w: resource identity is required", scim.ErrInvalid)
	}
	data, err := json.Marshal(d)
	if err != nil {
		return out, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	create := id == ""
	now := time.Now().UTC()
	created := now
	if !create {
		old, e := read(ctx, tx, k, id)
		if e != nil {
			return out, e
		}
		if e = precondition(old, match); e != nil {
			return out, e
		}
		created = old.Created
	} else {
		id = rand.Text()
	}
	nameKey := cases.Fold().String(norm.NFKC.String(name))
	if k == scim.Users {
		var other string
		e := tx.QueryRowContext(ctx, "SELECT id FROM resources WHERE kind='Users' AND id<>? AND (external_id=? OR name_key=?) LIMIT 1", id, external, nameKey).Scan(&other)
		if e == nil {
			return out, scim.ErrConflict
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return out, e
		}
	}
	// Validate references before writing; group-of-groups is not part of this profile.
	members := []scim.Document{}
	if k == scim.Groups {
		if raw, ok := d["members"]; ok {
			if err = json.Unmarshal(raw, &members); err != nil {
				return out, fmt.Errorf("%w: invalid members", scim.ErrInvalid)
			}
		}
		for _, member := range members {
			var kind scim.Kind
			err = tx.QueryRowContext(ctx, "SELECT kind FROM resources WHERE id=?", member.Text("value")).Scan(&kind)
			if errors.Is(err, sql.ErrNoRows) || err == nil && kind != scim.Users {
				return out, fmt.Errorf("%w: member must reference an existing user", scim.ErrInvalid)
			}
			if err != nil {
				return out, err
			}
		}
	}
	n, err := next(ctx, tx)
	if err != nil {
		return out, err
	}
	stamp := now.Format(time.RFC3339Nano)
	if create {
		_, err = tx.ExecContext(ctx, "INSERT INTO resources VALUES (?,?,?,?,?,?,?,?,?)", id, k, data, name, nameKey, external, n, created.Format(time.RFC3339Nano), stamp)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE resources SET document=?,name=?,name_key=?,external_id=?,version=?,modified=? WHERE id=?", data, name, nameKey, external, n, stamp, id)
	}
	if err != nil {
		return out, err
	}
	if k == scim.Groups {
		if _, err = tx.ExecContext(ctx, "DELETE FROM members WHERE group_id=?", id); err != nil {
			return out, err
		}
		for _, m := range members {
			if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO members VALUES (?,?)", id, m.Text("value")); err != nil {
				return out, err
			}
		}
		if create {
			var owner string
			e := tx.QueryRowContext(ctx, "SELECT group_id FROM aliases WHERE name=?", name).Scan(&owner)
			switch {
			case errors.Is(e, sql.ErrNoRows):
				_, err = tx.ExecContext(ctx, "INSERT INTO aliases VALUES (?,?)", name, id)
				if err == nil {
					err = audit(ctx, tx, n, "scim", "bind", id, name, "")
				}
			case e != nil:
				err = e
			default:
				err = audit(ctx, tx, n, "scim", "name-conflict", id, name, owner)
			}
			if err != nil {
				return out, err
			}
		}
	}
	action := "replace"
	if create {
		action = "create"
	}
	if err = audit(ctx, tx, n, "scim", action, id, "", ""); err != nil {
		return out, err
	}
	out = scim.Resource{ID: id, Kind: k, Document: d, Version: n, Created: created, Modified: now}
	return out, tx.Commit()
}

func (s *Store) Delete(ctx context.Context, k scim.Kind, id, match string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := read(ctx, tx, k, id)
	if err != nil {
		return err
	}
	if err = precondition(r, match); err != nil {
		return err
	}
	n, err := next(ctx, tx)
	if err != nil {
		return err
	}
	if k == scim.Users {
		rows, e := tx.QueryContext(ctx, "SELECT group_id FROM members WHERE user_id=?", id)
		if e != nil {
			return e
		}
		var ids []string
		for rows.Next() {
			var group string
			if e = rows.Scan(&group); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, group)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, group := range ids {
			g, e := read(ctx, tx, scim.Groups, group)
			if e != nil {
				return e
			}
			var members []scim.Document
			if e = json.Unmarshal(g.Document["members"], &members); e != nil {
				return e
			}
			retained := make([]scim.Document, 0, len(members))
			for _, m := range members {
				if m.Text("value") != id {
					retained = append(retained, m)
				}
			}
			g.Document["members"], e = json.Marshal(retained)
			if e != nil {
				return e
			}
			data, e := json.Marshal(g.Document)
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE resources SET document=?,version=?,modified=? WHERE id=?", data, n, time.Now().UTC().Format(time.RFC3339Nano), group); e != nil {
				return e
			}
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM resources WHERE id=?", id); err != nil {
		return err
	}
	if err = audit(ctx, tx, n, "scim", "delete", id, "", ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LookupUser(ctx context.Context, externalID string) (*directory.User, directory.Revision, error) {
	tx, err := s.db.BeginTx(ctx, nil)
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
	err = tx.QueryRowContext(ctx, "SELECT id FROM resources WHERE kind='Users' AND external_id=?", externalID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, rev, tx.Commit()
	}
	if err != nil {
		return nil, "", err
	}
	r, err := read(ctx, tx, scim.Users, id)
	if err != nil {
		return nil, "", err
	}
	u, err := r.Document.UserFacts()
	if err != nil {
		return nil, "", err
	}
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

func (s *Store) Bindings(ctx context.Context) (scim.BindingSnapshot, error) {
	out := scim.BindingSnapshot{Groups: []scim.GroupBinding{}}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	out.Revision, _, err = revision(ctx, tx)
	if err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.id,r.name,COALESCE(a.name,''), CASE WHEN a.name IS NOT NULL THEN 'bound' WHEN EXISTS(SELECT 1 FROM aliases WHERE name=r.name) THEN 'conflict' ELSE 'unbound' END
FROM resources r LEFT JOIN aliases a ON a.group_id=r.id WHERE r.kind='Groups'
UNION ALL SELECT a.group_id,'',a.name,'deleted' FROM aliases a WHERE NOT EXISTS(SELECT 1 FROM resources r WHERE r.id=a.group_id)
ORDER BY 2,1`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var g scim.GroupBinding
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
		return fmt.Errorf("%w: actor and policy alias are required", scim.ErrInvalid)
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
		return scim.ErrVersion
	}
	if _, err = read(ctx, tx, scim.Groups, id); err != nil {
		return err
	}
	var existing string
	err = tx.QueryRowContext(ctx, "SELECT name FROM aliases WHERE group_id=?", id).Scan(&existing)
	if err == nil && existing != alias {
		return fmt.Errorf("%w: group already has policy alias %q", scim.ErrConflict, existing)
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
func (s *Store) Audit(ctx context.Context) ([]scim.AuditEvent, error) {
	out := []scim.AuditEvent{}
	rows, err := s.db.QueryContext(ctx, "SELECT revision,time,actor,action,resource_id,alias,previous_id FROM audit ORDER BY sequence")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e scim.AuditEvent
		var stamp string
		if err = rows.Scan(&e.Revision, &stamp, &e.Actor, &e.Action, &e.ID, &e.Alias, &e.PreviousID); err != nil {
			return nil, err
		}
		if e.Time, err = time.Parse(time.RFC3339Nano, stamp); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
