// Package sqlitestore implements managed inventory using embedded SQLite.
// SQL and transaction ownership stay here; shared admission rules live in inventory.
package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/facts/storage"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
)

// Store owns host persistence, admission, and authorization lookups. Each
// mutation checks conflicts and commits the host, token, and audit changes in
// one transaction. Reads return independent, coherent snapshots;
// there is no application cache or separate index to rebuild after a restart.
type Store struct {
	db *sql.DB
}

func (m *Store) SupportsVersioning() bool { return true }

var _ inventory.Store = (*Store)(nil)
var _ inventory.Hosts = (*Store)(nil)

// Open opens a private SQLite database at path, creating its schema if
// needed. Storage, schema, or validation errors fail startup.
func Open(path string) (*Store, error) {
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	m := &Store{db: db}
	if err = m.initialize(); err == nil {
		err = m.validate()
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("opening managed inventory: %w", err)
	}
	return m, nil
}

func (m *Store) Close() error { return m.db.Close() }

func (m *Store) initialize() error {
	ctx := context.Background()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != 0 && version != 5 {
		return fmt.Errorf("unsupported inventory database version %d", version)
	}
	if version == 0 {
		_, err = tx.ExecContext(ctx, `
CREATE TABLE hosts (
 id TEXT PRIMARY KEY CHECK(length(id)=64 AND id NOT GLOB '*[^0-9a-f]*'),
 revision INTEGER NOT NULL CHECK(revision>0),
 status TEXT NOT NULL CHECK(status IN ('pending','active','denied')),
 principal_mode TEXT NOT NULL, realm TEXT NOT NULL,
 labels_null INTEGER NOT NULL CHECK(labels_null IN (0,1)),
 accounts_null INTEGER NOT NULL CHECK(accounts_null IN (0,1)),
 created TEXT NOT NULL, updated TEXT NOT NULL
);
CREATE INDEX host_status_realm ON hosts(status,realm);
CREATE TABLE names (host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, name TEXT NOT NULL, wildcard INTEGER NOT NULL CHECK(wildcard IN (0,1)), PRIMARY KEY(host_id,name));
CREATE INDEX hostname ON names(wildcard,name,host_id);
CREATE TABLE labels (host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, name TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(host_id,name));
CREATE TABLE accounts (host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, position INTEGER NOT NULL, name TEXT NOT NULL, PRIMARY KEY(host_id,position), UNIQUE(host_id,name));
CREATE TABLE tokens (host_id TEXT PRIMARY KEY, expires TEXT NOT NULL, used INTEGER NOT NULL CHECK(used IN (0,1)), revoked INTEGER NOT NULL CHECK(revoked IN (0,1)));
CREATE TABLE audit (host_id TEXT NOT NULL, time TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL);
PRAGMA user_version=5;`)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func storageError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", inventory.ErrStorage, err)
}

// recordIDs reads one bounded page and closes its cursor before callers read each
// host on the same connection.
func recordIDs(ctx context.Context, tx *sql.Tx, after string, limit int, pending bool) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM hosts WHERE id>? AND (?=0 OR status='pending') ORDER BY id LIMIT ?", after, pending, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func readHost(ctx context.Context, tx *sql.Tx, id string) (*inventory.Host, error) {
	h := &inventory.Host{ID: id}
	var labelsNull, accountsNull bool
	var created, updated string
	err := tx.QueryRowContext(ctx, "SELECT revision,status,principal_mode,realm,labels_null,accounts_null,created,updated FROM hosts WHERE id=?", id).Scan(&h.Version, &h.Status, &h.PrincipalMode, &h.Realm, &labelsNull, &accountsNull, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, inventory.ErrNotFound
	}
	if err != nil {
		return nil, storageError(err)
	}
	if h.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return nil, storageError(err)
	}
	if h.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated); err != nil {
		return nil, storageError(err)
	}
	if !labelsNull {
		h.Labels = map[string]string{}
	}
	if !accountsNull {
		h.Accounts = []string{}
	}
	rows, err := tx.QueryContext(ctx, "SELECT name FROM names WHERE host_id=? ORDER BY name", id)
	if err != nil {
		return nil, storageError(err)
	}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			break
		}
		h.Names = append(h.Names, name)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, storageError(err)
	}
	rows, err = tx.QueryContext(ctx, "SELECT name,value FROM labels WHERE host_id=?", id)
	if err != nil {
		return nil, storageError(err)
	}
	for rows.Next() {
		var name, value string
		if err = rows.Scan(&name, &value); err != nil {
			break
		}
		if labelsNull {
			err = fmt.Errorf("null labels have stored entries on host %s", id)
			break
		}
		h.Labels[name] = value
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, storageError(err)
	}
	rows, err = tx.QueryContext(ctx, "SELECT name FROM accounts WHERE host_id=? ORDER BY position", id)
	if err != nil {
		return nil, storageError(err)
	}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			break
		}
		if accountsNull {
			err = fmt.Errorf("null accounts have stored entries on host %s", id)
			break
		}
		h.Accounts = append(h.Accounts, name)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	return h, storageError(err)
}

func readToken(ctx context.Context, tx *sql.Tx, id string) (*inventory.EnrollmentToken, error) {
	t := &inventory.EnrollmentToken{ID: id}
	var expires string
	var used bool
	err := tx.QueryRowContext(ctx, "SELECT expires,used,revoked FROM tokens WHERE host_id=?", id).Scan(&expires, &used, &t.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, storageError(err)
	}
	if t.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires); err != nil {
		return nil, storageError(err)
	}
	if used {
		t.UsedBy = id
	}
	return t, nil
}

func (m *Store) validate() error {
	ctx := context.Background()
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	after := ""
	for {
		ids, err := recordIDs(ctx, tx, after, inventory.MaxPageLimit, false)
		if err != nil {
			return err
		}
		for _, id := range ids {
			h, err := readHost(ctx, tx, id)
			if err != nil {
				return err
			}
			if err = h.Validate(); err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
			if h.Status == inventory.StatusActive {
				if err = checkNames(ctx, tx, h.Names, id); err != nil {
					return err
				}
			}
		}
		if len(ids) == 0 {
			break
		}
		after = ids[len(ids)-1]
	}
	return tx.Commit()
}

// saveRecord replaces the typed record and its collections inside the caller's
// transaction. Null flags preserve null versus empty collections across reads.
func saveRecord(ctx context.Context, tx *sql.Tx, h *inventory.Host, create bool) error {
	p := h
	fields := []any{h.Status, p.PrincipalMode, p.Realm, p.Labels == nil, p.Accounts == nil, h.CreatedAt.UTC().Format(time.RFC3339Nano), h.UpdatedAt.UTC().Format(time.RFC3339Nano), h.ID}
	var err error
	if create {
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM hosts WHERE id=?)", h.ID).Scan(&exists); err != nil {
			return storageError(err)
		}
		if exists {
			return inventory.ErrConflict
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO hosts (revision,status,principal_mode,realm,labels_null,accounts_null,created,updated,id) VALUES (1,?,?,?,?,?,?,?,?)", fields...)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE hosts SET revision=revision+1,status=?,principal_mode=?,realm=?,labels_null=?,accounts_null=?,created=?,updated=? WHERE id=?", fields...)
	}
	if err != nil {
		return storageError(err)
	}
	for _, table := range []string{"names", "labels", "accounts"} {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE host_id=?", h.ID); err != nil {
			return storageError(err)
		}
	}
	for _, name := range p.Names {
		if _, err = tx.ExecContext(ctx, "INSERT INTO names VALUES (?,?,?)", h.ID, name, strings.ContainsAny(name, "*?")); err != nil {
			return storageError(err)
		}
	}
	for name, value := range p.Labels {
		if _, err = tx.ExecContext(ctx, "INSERT INTO labels VALUES (?,?,?)", h.ID, name, value); err != nil {
			return storageError(err)
		}
	}
	for i, name := range p.Accounts {
		if _, err = tx.ExecContext(ctx, "INSERT INTO accounts VALUES (?,?,?)", h.ID, i, name); err != nil {
			return storageError(err)
		}
	}
	return nil
}

// finish commits the mutation and supplied audit event together.
func finish(ctx context.Context, tx *sql.Tx, event inventory.AuditEvent) error {
	// The event is persisted exactly as supplied by the caller.
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit (host_id,time,actor,action) VALUES (?,?,?,?)", event.Resource, event.At.Format(time.RFC3339Nano), event.Actor, event.Action); err != nil {
		return storageError(err)
	}
	return storageError(tx.Commit())
}

// checkNames only considers active hosts. An immediate write transaction spans
// the check and mutation, preventing duplicate admissions across connections.
func checkNames(ctx context.Context, tx *sql.Tx, names []string, except string) error {
	for _, name := range names {
		var owner string
		err := tx.QueryRowContext(ctx, "SELECT host_id FROM names JOIN hosts ON hosts.id=names.host_id WHERE name=? AND wildcard=? AND status='active' AND host_id<>? LIMIT 1", name, strings.ContainsAny(name, "*?"), except).Scan(&owner)
		if err == nil {
			return fmt.Errorf("%w: name %s is active on host %s", inventory.ErrConflict, name, owner)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return storageError(err)
		}
	}
	return nil
}

// UpsertHost applies the write conditions and commits host, token, and audit
// changes in one SQLite transaction. Enrollment and review policy stay upstream.
func (m *Store) UpsertHost(ctx context.Context, proposed inventory.Host, conditions inventory.WriteConditions, event inventory.AuditEvent) (*inventory.Host, error) {
	id := proposed.ID
	if !validID(id) {
		if conditions.ConsumeToken {
			return nil, inventory.ErrToken
		}
		return nil, fmt.Errorf("invalid host id")
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	current, err := readHost(ctx, tx, id)
	if err != nil && !errors.Is(err, inventory.ErrNotFound) {
		return nil, err
	}
	if conditions.ExpectedVersion != "" && (current == nil || current.Version != conditions.ExpectedVersion) {
		return nil, inventory.ErrVersion
	}
	var token *inventory.EnrollmentToken
	if current == nil || conditions.ConsumeToken {
		token, err = readToken(ctx, tx, id)
		if err != nil {
			return nil, err
		}
	}
	if current != nil && (conditions.CreateOnly || conditions.ConsumeToken) {
		if conditions.ConsumeToken && (token == nil || token.UsedBy == "") {
			return nil, inventory.ErrToken
		}
		if inventory.SameHostFacts(*current, proposed) {
			return current, nil
		}
		if conditions.ConsumeToken {
			return nil, inventory.ErrToken
		}
		return nil, inventory.ErrConflict
	}
	var h inventory.Host
	if current == nil {
		if conditions.ConsumeToken {
			if token == nil || token.Revoked || token.UsedBy != "" || !time.Now().UTC().Before(token.ExpiresAt) {
				return nil, inventory.ErrToken
			}
		} else if token != nil {
			// An issued token ID can only be claimed by consuming that token.
			return nil, inventory.ErrConflict
		}
		h, err = inventory.Creation(id, proposed, event.At)
	} else {
		h, err = inventory.Replacement(*current, proposed, conditions.ExpectedVersion, event.At)
	}
	if err != nil {
		return nil, err
	}
	if h.Status == inventory.StatusActive {
		if err = checkNames(ctx, tx, h.Names, id); err != nil {
			return nil, err
		}
	}
	if err = saveRecord(ctx, tx, &h, current == nil); err != nil {
		return nil, err
	}
	if conditions.ConsumeToken {
		if _, err = tx.ExecContext(ctx, "UPDATE tokens SET used=1 WHERE host_id=?", id); err != nil {
			return nil, storageError(err)
		}
	}
	result, err := readHost(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = finish(ctx, tx, event); err != nil {
		return nil, err
	}
	return result, nil
}

func (m *Store) RemoveHost(ctx context.Context, id string, expectedVersion string, event inventory.AuditEvent) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	current, err := readHost(ctx, tx, id)
	if err != nil {
		return err
	}
	if expectedVersion != "" && expectedVersion != current.Version {
		return inventory.ErrVersion
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM hosts WHERE id=?", id); err != nil {
		return storageError(err)
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM tokens WHERE host_id=?", id); err != nil {
		return storageError(err)
	}
	return finish(ctx, tx, event)
}
func (m *Store) GetHost(ctx context.Context, id string) (*inventory.Host, error) {
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	result, err := readHost(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	return result, storageError(tx.Commit())
}
func (m *Store) ListHosts(ctx context.Context, after string, limit int, pending bool) ([]inventory.Host, error) {
	limit, err := recordPage(after, limit)
	if err != nil {
		return nil, err
	}
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	ids, err := recordIDs(ctx, tx, after, limit, pending)
	if err != nil {
		return nil, storageError(err)
	}
	result := []inventory.Host{}
	for _, id := range ids {
		row, err := readHost(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, *row)
	}
	return result, storageError(tx.Commit())
}

func (m *Store) CreateToken(ctx context.Context, id string, lifetime time.Duration, event inventory.AuditEvent) (inventory.EnrollmentToken, error) {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return inventory.EnrollmentToken{}, fmt.Errorf("token lifetime must be positive and no more than 24h")
	}
	token := inventory.EnrollmentToken{ID: id, ExpiresAt: event.At.Add(lifetime)}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return inventory.EnrollmentToken{}, storageError(err)
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM tokens WHERE host_id=? UNION ALL SELECT 1 FROM hosts WHERE id=?)", id, id).Scan(&exists); err != nil {
		return inventory.EnrollmentToken{}, storageError(err)
	}
	if exists {
		return inventory.EnrollmentToken{}, inventory.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO tokens VALUES (?,?,0,0)", id, token.ExpiresAt.Format(time.RFC3339Nano)); err != nil {
		return inventory.EnrollmentToken{}, storageError(err)
	}
	return token, finish(ctx, tx, event)
}

func (m *Store) RevokeToken(ctx context.Context, id string, event inventory.AuditEvent) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	t, err := readToken(ctx, tx, id)
	if err != nil {
		return err
	}
	if t == nil {
		return inventory.ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tokens SET revoked=1 WHERE host_id=?", id); err != nil {
		return storageError(err)
	}
	return finish(ctx, tx, event)
}

// Audit uses SQLite row positions only to resume this backend's scan. They are
// not audit event fields or a cross-backend ordering guarantee.
func (m *Store) Audit(ctx context.Context, cursor string, limit int) ([]inventory.AuditEvent, string, error) {
	limit, err := pageLimit(limit)
	if err != nil {
		return nil, "", err
	}
	var after int64
	if cursor != "" {
		var err error
		after, err = strconv.ParseInt(cursor, 10, 64)
		if err != nil || after < 0 {
			return nil, "", fmt.Errorf("invalid audit cursor")
		}
	}
	rows, err := m.db.QueryContext(ctx, "SELECT rowid,time,actor,action,host_id FROM audit WHERE rowid>? ORDER BY rowid LIMIT ?", after, limit+1)
	if err != nil {
		return nil, "", storageError(err)
	}
	defer rows.Close()
	events := []inventory.AuditEvent{}
	var last int64
	for rows.Next() {
		if len(events) == limit {
			return events, strconv.FormatInt(last, 10), nil
		}
		var e inventory.AuditEvent
		var stamp string
		if err = rows.Scan(&last, &stamp, &e.Actor, &e.Action, &e.Resource); err != nil {
			return nil, "", storageError(err)
		}
		if e.At, err = time.Parse(time.RFC3339Nano, stamp); err != nil {
			return nil, "", storageError(err)
		}
		events = append(events, e)
	}
	if err = rows.Err(); err != nil {
		return nil, "", storageError(err)
	}
	return events, "", nil
}

// LookupHost reads current host facts in one snapshot. Exact names take
// precedence over active wildcard names.
func (m *Store) LookupHost(ctx context.Context, name string) (*inventory.Host, error) {
	name = hostpattern.NormalizeName(name)
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	var id string
	wildcard := false
	err = tx.QueryRowContext(ctx, "SELECT host_id FROM names JOIN hosts ON hosts.id=names.host_id WHERE name=? AND wildcard=0 AND status='active'", name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		rows, queryErr := tx.QueryContext(ctx, "SELECT host_id,name FROM names JOIN hosts ON hosts.id=names.host_id WHERE wildcard=1 AND status='active' ORDER BY host_id,name")
		if queryErr != nil {
			return nil, storageError(queryErr)
		}
		for rows.Next() {
			var candidate, raw string
			if queryErr = rows.Scan(&candidate, &raw); queryErr != nil {
				queryErr = storageError(queryErr)
				break
			}
			pattern, parseErr := hostpattern.Parse(raw)
			if parseErr != nil {
				queryErr = storageError(parseErr)
				break
			}
			if pattern.Match(name) {
				if id != "" && id != candidate {
					queryErr = fmt.Errorf("%w: hostname %s matches wildcard names on hosts %s and %s", inventory.ErrConflict, name, id, candidate)
					break
				}
				id = candidate
				wildcard = true
			}
		}
		if queryErr == nil {
			queryErr = storageError(rows.Err())
		}
		rows.Close()
		if queryErr != nil {
			return nil, queryErr
		}
		if id == "" {
			return nil, storageError(tx.Commit())
		}
		err = nil
	}
	if err != nil {
		return nil, storageError(err)
	}
	h, err := readHost(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if wildcard {
		// The matched record supplies facts, not a stored identity for this hostname.
		h = &inventory.Host{Names: []string{name}, Labels: h.Labels, Accounts: h.Accounts,
			PrincipalMode: h.PrincipalMode, Realm: h.Realm, Status: inventory.StatusActive}
	}
	return h, storageError(tx.Commit())
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Page bounds apply before reading rows, so memory use does not grow with the
// number of stored records. IDs are already canonical hexadecimal strings.
func recordPage(after string, limit int) (int, error) {
	if after != "" && !validID(after) {
		return 0, fmt.Errorf("after must be a full record ID")
	}
	return pageLimit(limit)
}

func pageLimit(limit int) (int, error) {
	if limit == 0 {
		return inventory.DefaultPageLimit, nil
	}
	if limit < 1 || limit > inventory.MaxPageLimit {
		return 0, fmt.Errorf("limit must be between 1 and %d", inventory.MaxPageLimit)
	}
	return limit, nil
}
