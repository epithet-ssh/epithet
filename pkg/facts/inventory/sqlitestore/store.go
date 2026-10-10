// Package sqlitestore implements managed inventory using embedded SQLite.
// SQL, admission checks, and transaction ownership stay here; callers use inventory.Store.
package sqlitestore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/facts/storage"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/principal"
)

// Store owns host persistence, admission, and authorization lookups. Each
// mutation checks conflicts and commits the host, token, audit, and inventory
// revision in one transaction. Reads return independent, coherent snapshots;
// there is no application cache or separate index to rebuild after a restart.
type Store struct {
	db    *sql.DB
	newID func() (string, error)
	// <review>
	// why is this an attribute? Does it ever actually change?
	// </review>
}

var _ inventory.Store = (*Store)(nil)

// Open opens a private SQLite database at path, creating its schema if
// needed. Storage, schema, or validation errors fail startup.
func Open(path string) (*Store, error) {
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	m := &Store{db: db, newID: randomSecret}
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
	if version != 0 && version != 1 {
		return fmt.Errorf("unsupported inventory database version %d", version)
	}
	if version == 0 {
		_, err = tx.ExecContext(ctx, `
CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), instance TEXT NOT NULL, revision INTEGER NOT NULL);
CREATE TABLE hosts (
 id TEXT PRIMARY KEY CHECK(length(id)=64 AND id NOT GLOB '*[^0-9a-f]*'),
 revision INTEGER NOT NULL CHECK(revision>0),
 status TEXT NOT NULL CHECK(status IN ('pending','active','denied')),
 principal_mode TEXT NOT NULL, realm TEXT NOT NULL, pattern TEXT NOT NULL,
 labels_null INTEGER NOT NULL CHECK(labels_null IN (0,1)),
 accounts_null INTEGER NOT NULL CHECK(accounts_null IN (0,1)),
 created TEXT NOT NULL, updated TEXT NOT NULL
);
CREATE INDEX host_status_realm ON hosts(status,realm);
CREATE TABLE names (host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, name TEXT NOT NULL, PRIMARY KEY(host_id,name));
CREATE INDEX hostname ON names(name,host_id);
CREATE TABLE labels (host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, name TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(host_id,name));
CREATE TABLE accounts (host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, position INTEGER NOT NULL, name TEXT NOT NULL, PRIMARY KEY(host_id,position), UNIQUE(host_id,name));
CREATE TABLE tokens (host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE, expires TEXT NOT NULL, used INTEGER NOT NULL CHECK(used IN (0,1)), revoked INTEGER NOT NULL CHECK(revoked IN (0,1)));
CREATE TABLE audit (sequence INTEGER PRIMARY KEY, host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, time TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL);
PRAGMA user_version=1;`)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO state VALUES (1, ?, 0)", rand.Text()); err != nil {
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

// hostIDs reads one bounded page and closes its cursor before callers read each
// host on the same connection.
func hostIDs(ctx context.Context, tx *sql.Tx, after string, limit int, pending bool) ([]string, error) {
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

func readHost(ctx context.Context, tx *sql.Tx, id string) (*inventory.HostRecord, error) {
	h := &inventory.HostRecord{ID: id}
	var labelsNull, accountsNull bool
	var created, updated string
	err := tx.QueryRowContext(ctx, "SELECT revision,status,principal_mode,realm,pattern,labels_null,accounts_null,created,updated FROM hosts WHERE id=?", id).Scan(&h.Revision, &h.Status, &h.Proposal.PrincipalMode, &h.Proposal.Realm, &h.Proposal.Pattern, &labelsNull, &accountsNull, &created, &updated)
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
		h.Proposal.Labels = map[string]string{}
	}
	if !accountsNull {
		h.Proposal.Accounts = []string{}
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
		h.Proposal.Names = append(h.Proposal.Names, name)
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
		h.Proposal.Labels[name] = value
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
		h.Proposal.Accounts = append(h.Proposal.Accounts, name)
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
	if _, err = inventoryRevision(ctx, tx); err != nil {
		return err
	}
	after := ""
	for {
		ids, err := hostIDs(ctx, tx, after, inventory.MaxPageLimit, false)
		if err != nil {
			return err
		}
		for _, id := range ids {
			h, err := readHost(ctx, tx, id)
			if err != nil {
				return err
			}
			t, err := readToken(ctx, tx, id)
			if err != nil {
				return err
			}
			if t != nil && (t.ExpiresAt.IsZero() || t.UsedBy == "" && !t.Revoked && h.Status != "pending") {
				return fmt.Errorf("%s: invalid token metadata", id)
			}
			if !(emptyProposal(h.Proposal) && t != nil && t.UsedBy == "" && h.Status != "active") {
				if err = h.Proposal.Validate(); err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
			}
			if h.Status == "active" {
				if err = m.checkRealm(ctx, tx, h.Proposal, id); err != nil {
					return err
				}
				if err = checkNames(ctx, tx, h.Proposal, id); err != nil {
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

func inventoryRevision(ctx context.Context, tx *sql.Tx) (string, error) {
	var instance string
	var revision uint64
	err := tx.QueryRowContext(ctx, "SELECT instance,revision FROM state WHERE singleton=1").Scan(&instance, &revision)
	return fmt.Sprintf("managed:%s:%d", instance, revision), storageError(err)
}

// saveHost replaces the typed record and its collections inside the caller's
// transaction. Null flags preserve null versus empty collections across reads.
func saveHost(ctx context.Context, tx *sql.Tx, h *inventory.HostRecord, create bool) error {
	p := h.Proposal
	fields := []any{h.Revision, h.Status, p.PrincipalMode, p.Realm, p.Pattern, p.Labels == nil, p.Accounts == nil, h.CreatedAt.UTC().Format(time.RFC3339Nano), h.UpdatedAt.UTC().Format(time.RFC3339Nano), h.ID}
	var err error
	if create {
		_, err = tx.ExecContext(ctx, "INSERT INTO hosts (revision,status,principal_mode,realm,pattern,labels_null,accounts_null,created,updated,id) VALUES (?,?,?,?,?,?,?,?,?,?)", fields...)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE hosts SET revision=?,status=?,principal_mode=?,realm=?,pattern=?,labels_null=?,accounts_null=?,created=?,updated=? WHERE id=?", fields...)
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
		if _, err = tx.ExecContext(ctx, "INSERT INTO names VALUES (?,?)", h.ID, name); err != nil {
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

// finish commits the mutation, audit, and inventory revision together. Removal
// keeps the existing contract: cascading deletion also removes the host's audit.
func finish(ctx context.Context, tx *sql.Tx, id, actor, action string) error {
	if _, err := tx.ExecContext(ctx, "UPDATE state SET revision=revision+1 WHERE singleton=1"); err != nil {
		return storageError(err)
	}
	if action != "remove" {
		// The persistent revision counter survives audit deletion. Using it as
		// the event sequence prevents a deleted last event's cursor being reused.
		if _, err := tx.ExecContext(ctx, "INSERT INTO audit (sequence,host_id,time,actor,action) SELECT revision,?,?,?,? FROM state WHERE singleton=1", id, time.Now().UTC().Format(time.RFC3339Nano), actor, action); err != nil {
			return storageError(err)
		}
	}
	return storageError(tx.Commit())
}

// checkNames only considers active hosts. An immediate write transaction spans
// the check and mutation, preventing duplicate admissions across connections.
func checkNames(ctx context.Context, tx *sql.Tx, p inventory.Proposal, except string) error {
	if p.Pattern != "" {
		var owner string
		err := tx.QueryRowContext(ctx, "SELECT id FROM hosts WHERE pattern=? AND status='active' AND id<>? LIMIT 1", p.Pattern, except).Scan(&owner)
		if err == nil {
			return fmt.Errorf("%w: pattern %s is active on record %s", inventory.ErrConflict, p.Pattern, owner)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return storageError(err)
		}
	}
	for _, name := range p.Names {
		var owner string
		err := tx.QueryRowContext(ctx, "SELECT host_id FROM names JOIN hosts ON hosts.id=names.host_id WHERE name=? AND status='active' AND host_id<>? LIMIT 1", name, except).Scan(&owner)
		if err == nil {
			return fmt.Errorf("%w: name %s is active on host %s", inventory.ErrConflict, name, owner)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return storageError(err)
		}
	}
	return nil
}

// AddPattern declares an active fleet rule as an administrative operation.
// Its attributes and admission checks are the same as an approved proposal;
// creation and its audit event commit together.
func (m *Store) AddPattern(ctx context.Context, actor string, p inventory.Proposal) (*inventory.HostRecord, error) {
	if p.Pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	if err = m.conflict(ctx, tx, p, ""); err != nil {
		return nil, err
	}
	id, err := m.unusedID(ctx, tx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	h := &inventory.HostRecord{ID: id, Revision: 1, Status: "active", Proposal: p, CreatedAt: now, UpdatedAt: now}
	if err = saveHost(ctx, tx, h, true); err != nil {
		return nil, err
	}
	h, err = readHost(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = finish(ctx, tx, id, actor, "add-pattern"); err != nil {
		return nil, err
	}
	return h, nil
}

func (m *Store) conflict(ctx context.Context, tx *sql.Tx, p inventory.Proposal, except string) error {
	if err := m.checkRealm(ctx, tx, p, except); err != nil {
		return err
	}
	return checkNames(ctx, tx, p, except)
}

// checkRealm preserves per-host identity for generated realms and identical
// authorization attributes for shared named realms. Realm names are attributes
// of records; there is no separate registry or declaration step.
func (m *Store) checkRealm(ctx context.Context, tx *sql.Tx, p inventory.Proposal, except string) error {
	realm := principal.Realm(p.Realm)
	if realm == "" {
		return nil
	}
	after := ""
	for {
		rows, err := tx.QueryContext(ctx, "SELECT id FROM hosts WHERE status='active' AND realm=? AND id<>? AND id>? ORDER BY id LIMIT ?", p.Realm, except, after, inventory.MaxPageLimit)
		if err != nil {
			return storageError(err)
		}
		var ids []string
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				break
			}
			ids = append(ids, id)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return storageError(err)
		}
		for _, id := range ids {
			if realm.IsGeneratedHost() {
				return fmt.Errorf("%w: principal realm is already active on host %s", inventory.ErrConflict, id)
			}
			member, err := readHost(ctx, tx, id)
			if err != nil {
				return err
			}
			if !sameAuthorization(member.Proposal.Labels, member.Proposal.Accounts, p.Labels, p.Accounts) {
				return fmt.Errorf("%w: realm %q has different authorization attributes from host %s", inventory.ErrConflict, realm, id)
			}
		}
		if len(ids) == 0 {
			break
		}
		after = ids[len(ids)-1]
	}

	return nil
}

func (m *Store) unusedID(ctx context.Context, tx *sql.Tx) (string, error) {
	for {
		id, err := m.newID()
		if err != nil {
			return "", err
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM hosts WHERE id=?)", id).Scan(&exists); err != nil {
			return "", storageError(err)
		}
		if !exists {
			return id, nil
		}
	}
}

func (m *Store) Enroll(ctx context.Context, p inventory.Proposal, token string) (*inventory.HostRecord, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	h := &inventory.HostRecord{Revision: 1, Status: "pending", Proposal: p, CreatedAt: now, UpdatedAt: now}
	if token != "" {
		if !validID(token) {
			return nil, inventory.ErrToken
		}
		reserved, err := readHost(ctx, tx, token)
		if errors.Is(err, inventory.ErrNotFound) {
			return nil, inventory.ErrToken
		}
		if err != nil {
			return nil, err
		}
		t, err := readToken(ctx, tx, token)
		if err != nil {
			return nil, err
		}
		if reserved.Status != "pending" || t == nil || t.Revoked || t.UsedBy != "" || !now.Before(t.ExpiresAt) {
			return nil, inventory.ErrToken
		}
		if err = m.conflict(ctx, tx, p, ""); err != nil {
			return nil, err
		}
		h.ID, h.Status, h.CreatedAt, h.Revision = token, "active", reserved.CreatedAt, reserved.Revision+1
		if _, err = tx.ExecContext(ctx, "UPDATE tokens SET used=1 WHERE host_id=?", token); err != nil {
			return nil, storageError(err)
		}
	} else {
		var pending int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM hosts WHERE status='pending'").Scan(&pending); err != nil {
			return nil, storageError(err)
		}
		if pending >= 1000 {
			return nil, fmt.Errorf("pending enrollment queue is full")
		}
		if h.ID, err = m.unusedID(ctx, tx); err != nil {
			return nil, err
		}
	}
	if err = saveHost(ctx, tx, h, token == ""); err != nil {
		return nil, err
	}
	// Read back detached collections before committing; callers never share the
	// slices or maps passed in their proposal with the returned snapshot.
	h, err = readHost(ctx, tx, h.ID)
	if err != nil {
		return nil, err
	}
	if err = finish(ctx, tx, h.ID, "host", "enroll"); err != nil {
		return nil, err
	}
	return h, nil
}

func (m *Store) Change(ctx context.Context, actor, action, id string, revision uint64, p *inventory.Proposal) (*inventory.HostRecord, error) {
	if p != nil {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	h, err := readHost(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if revision == 0 || h.Revision != revision {
		return nil, inventory.ErrRevision
	}
	switch action {
	case "edit":
		if p == nil {
			return nil, fmt.Errorf("host proposal is required")
		}
		if h.Status != "pending" && h.Status != "active" {
			return nil, fmt.Errorf("only pending or active records can be edited")
		}
		if h.Status == "active" {
			if err = m.conflict(ctx, tx, *p, id); err != nil {
				return nil, err
			}
		}
		h.Proposal = *p
	case "approve":
		if h.Status != "pending" {
			return nil, fmt.Errorf("only pending records can be approved")
		}
		if err = h.Proposal.Validate(); err != nil {
			return nil, fmt.Errorf("host attributes are required before approval: %w", err)
		}
		if err = m.conflict(ctx, tx, h.Proposal, id); err != nil {
			return nil, err
		}
		h.Status = "active"
	case "deny":
		if h.Status != "pending" {
			return nil, fmt.Errorf("only pending records can be denied")
		}
		h.Status = "denied"
	case "remove":
		if _, err = tx.ExecContext(ctx, "DELETE FROM hosts WHERE id=?", id); err != nil {
			return nil, storageError(err)
		}
		return nil, finish(ctx, tx, id, actor, action)
	default:
		return nil, fmt.Errorf("unknown inventory action")
	}
	if h.Status != "pending" {
		if _, err = tx.ExecContext(ctx, "UPDATE tokens SET revoked=1 WHERE host_id=? AND used=0", id); err != nil {
			return nil, storageError(err)
		}
	}
	h.Revision++
	h.UpdatedAt = time.Now().UTC()
	if err = saveHost(ctx, tx, h, false); err != nil {
		return nil, err
	}
	h, err = readHost(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = finish(ctx, tx, id, actor, action); err != nil {
		return nil, err
	}
	return h, nil
}

func (m *Store) Get(ctx context.Context, id string) (*inventory.HostRecord, error) {
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	h, err := readHost(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	return h, storageError(tx.Commit())
}

func (m *Store) List(ctx context.Context, after string, limit int, pending bool) ([]inventory.HostRecord, error) {
	limit, err := recordPage(after, limit)
	if err != nil {
		return nil, err
	}
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	ids, err := hostIDs(ctx, tx, after, limit, pending)
	if err != nil {
		return nil, storageError(err)
	}
	hosts := []inventory.HostRecord{}
	for _, id := range ids {
		h, err := readHost(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, *h)
	}
	return hosts, storageError(tx.Commit())
}

func (m *Store) CreateToken(ctx context.Context, actor string, lifetime time.Duration) (inventory.EnrollmentToken, error) {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return inventory.EnrollmentToken{}, fmt.Errorf("token lifetime must be positive and no more than 24h")
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return inventory.EnrollmentToken{}, storageError(err)
	}
	defer tx.Rollback()
	id, err := m.unusedID(ctx, tx)
	if err != nil {
		return inventory.EnrollmentToken{}, err
	}
	now := time.Now().UTC()
	token := inventory.EnrollmentToken{ID: id, ExpiresAt: now.Add(lifetime)}
	h := &inventory.HostRecord{ID: id, Revision: 1, Status: "pending", CreatedAt: now, UpdatedAt: now}
	if err = saveHost(ctx, tx, h, true); err != nil {
		return inventory.EnrollmentToken{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO tokens VALUES (?,?,0,0)", id, token.ExpiresAt.Format(time.RFC3339Nano)); err != nil {
		return inventory.EnrollmentToken{}, storageError(err)
	}
	return token, finish(ctx, tx, id, actor, "token-create")
}

func (m *Store) Tokens(ctx context.Context, after string, limit int) ([]inventory.EnrollmentToken, error) {
	limit, err := recordPage(after, limit)
	if err != nil {
		return nil, err
	}
	rows, err := m.db.QueryContext(ctx, "SELECT host_id,expires,used,revoked FROM tokens WHERE host_id>? ORDER BY host_id LIMIT ?", after, limit)
	if err != nil {
		return nil, storageError(err)
	}
	defer rows.Close()
	tokens := []inventory.EnrollmentToken{}
	for rows.Next() {
		var t inventory.EnrollmentToken
		var expires string
		var used bool
		if err = rows.Scan(&t.ID, &expires, &used, &t.Revoked); err != nil {
			return nil, storageError(err)
		}
		if t.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires); err != nil {
			return nil, storageError(err)
		}
		if used {
			t.UsedBy = t.ID
		}
		tokens = append(tokens, t)
	}
	return tokens, storageError(rows.Err())
}

func (m *Store) RevokeToken(ctx context.Context, actor, id string) error {
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
	if _, err = tx.ExecContext(ctx, "UPDATE hosts SET revision=revision+1,updated=? WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
		return storageError(err)
	}
	return finish(ctx, tx, id, actor, "token-revoke")
}

func (m *Store) Audit(ctx context.Context, after inventory.AuditSequence, limit int) ([]inventory.AuditEvent, error) {
	limit, err := pageLimit(limit)
	if err != nil {
		return nil, err
	}
	rows, err := m.db.QueryContext(ctx, "SELECT sequence,time,actor,action,host_id FROM audit WHERE sequence>? ORDER BY sequence LIMIT ?", after, limit)
	if err != nil {
		return nil, storageError(err)
	}
	defer rows.Close()
	events := []inventory.AuditEvent{}
	for rows.Next() {
		var e inventory.AuditEvent
		var at string
		if err = rows.Scan(&e.Sequence, &at, &e.Actor, &e.Action, &e.Resource); err != nil {
			return nil, storageError(err)
		}
		if e.At, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return nil, storageError(err)
		}
		events = append(events, e)
	}
	return events, storageError(rows.Err())
}

// LookupHost reads current host facts and the inventory revision in the same
// snapshot. Exact names take precedence over active pattern records.
func (m *Store) LookupHost(ctx context.Context, name string) (*inventory.ResolvedHost, string, error) {
	name = hostpattern.NormalizeName(name)
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", storageError(err)
	}
	defer tx.Rollback()
	revision, err := inventoryRevision(ctx, tx)
	if err != nil {
		return nil, "", err
	}
	var id string
	err = tx.QueryRowContext(ctx, "SELECT host_id FROM names JOIN hosts ON hosts.id=names.host_id WHERE name=? AND status='active'", name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		rows, queryErr := tx.QueryContext(ctx, "SELECT id,pattern FROM hosts WHERE status='active' AND pattern<>'' ORDER BY id")
		if queryErr != nil {
			return nil, "", storageError(queryErr)
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
				if id != "" {
					queryErr = fmt.Errorf("%w: hostname %s matches pattern records %s and %s", inventory.ErrConflict, name, id, candidate)
					break
				}
				id = candidate
			}
		}
		if queryErr == nil {
			queryErr = storageError(rows.Err())
		}
		rows.Close()
		if queryErr != nil {
			return nil, "", queryErr
		}
		if id == "" {
			return nil, revision, storageError(tx.Commit())
		}
		err = nil
	}
	if err != nil {
		return nil, "", storageError(err)
	}
	h, err := readHost(ctx, tx, id)
	if err != nil {
		return nil, "", err
	}
	p := h.Proposal
	if p.Pattern != "" {
		p.Names = []string{name}
	}
	resolved := &inventory.ResolvedHost{Policy: inventory.Host{Names: p.Names, Labels: p.Labels, Accounts: p.Accounts}, PrincipalMode: p.PrincipalMode, Realm: principal.Realm(p.Realm)}
	return resolved, revision, storageError(tx.Commit())
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
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

// emptyProposal identifies a reservation that has not supplied any host attributes yet.
// It is permitted only on non-active host records with enrollment metadata.
func emptyProposal(p inventory.Proposal) bool {
	return p.Names == nil && p.Pattern == "" && p.Labels == nil && p.Accounts == nil && p.PrincipalMode == "" && p.Realm == ""
}

// sameAuthorization compares the authorization attributes shared by all realm members.
// Account order is irrelevant; unrestricted (nil) differs from no accounts ([]).
func sameAuthorization(previousLabels map[string]string, previousAccounts []string, labels map[string]string, accounts []string) bool {
	if !maps.Equal(previousLabels, labels) || (previousAccounts == nil) != (accounts == nil) {
		return false
	}
	previous, proposed := slices.Clone(previousAccounts), slices.Clone(accounts)
	slices.Sort(previous)
	slices.Sort(proposed)
	return slices.Equal(previous, proposed)
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
