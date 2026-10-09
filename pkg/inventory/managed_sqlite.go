package inventory

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/internal/sqlitedb"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/principal"
)

// Managed owns host persistence, admission, and authorization lookups. Each
// mutation checks conflicts and commits the host, token, audit, and inventory
// revision in one transaction. Reads return independent, coherent snapshots;
// there is no application cache or separate index to rebuild after a restart.
type Managed struct {
	db    *sql.DB
	newID func() (string, error)
	// <review>
	// why is this an attribute? Does it ever actually change?
	// </review>
}

// OpenManaged opens a private SQLite database at path, creating its schema if
// needed. Storage, schema, or validation errors fail startup.
func OpenManaged(path string) (*Managed, error) {
	db, err := sqlitedb.Open(path)
	if err != nil {
		return nil, err
	}
	m := &Managed{db: db, newID: RandomSecret}
	if err = m.initialize(); err == nil {
		err = m.validate()
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("opening managed inventory: %w", err)
	}
	return m, nil
}

func (m *Managed) Close() error { return m.db.Close() }

func (m *Managed) initialize() error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != 0 && version != 1 {
		return fmt.Errorf("unsupported inventory database version %d", version)
	}
	if version == 0 {
		_, err = tx.Exec(`
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
		if _, err = tx.Exec("INSERT INTO state VALUES (1, ?, 0)", rand.Text()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func storageError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrStorage, err)
}

// hostIDs closes its cursor before callers read each host on the same connection.
func hostIDs(tx *sql.Tx) ([]string, error) {
	rows, err := tx.Query("SELECT id FROM hosts ORDER BY id")
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

func readHost(tx *sql.Tx, id string) (*HostRecord, error) {
	h := &HostRecord{ID: id}
	var labelsNull, accountsNull bool
	var created, updated string
	err := tx.QueryRow("SELECT revision,status,principal_mode,realm,pattern,labels_null,accounts_null,created,updated FROM hosts WHERE id=?", id).Scan(&h.Revision, &h.Status, &h.Proposal.PrincipalMode, &h.Proposal.Realm, &h.Proposal.Pattern, &labelsNull, &accountsNull, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
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
	rows, err := tx.Query("SELECT name FROM names WHERE host_id=? ORDER BY name", id)
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
	rows, err = tx.Query("SELECT name,value FROM labels WHERE host_id=?", id)
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
	rows, err = tx.Query("SELECT name FROM accounts WHERE host_id=? ORDER BY position", id)
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

func readToken(tx *sql.Tx, id string) (*EnrollmentToken, error) {
	t := &EnrollmentToken{ID: id}
	var expires string
	var used bool
	err := tx.QueryRow("SELECT expires,used,revoked FROM tokens WHERE host_id=?", id).Scan(&expires, &used, &t.Revoked)
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

func (m *Managed) validate() error {
	tx, err := m.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = inventoryRevision(tx); err != nil {
		return err
	}
	ids, err := hostIDs(tx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		h, err := readHost(tx, id)
		if err != nil {
			return err
		}
		t, err := readToken(tx, id)
		if err != nil {
			return err
		}
		if t != nil && (t.ExpiresAt.IsZero() || t.UsedBy == "" && !t.Revoked && h.Status != "pending") {
			return fmt.Errorf("%s: invalid token metadata", id)
		}
		if !(h.Proposal.empty() && t != nil && t.UsedBy == "" && h.Status != "active") {
			if err = h.Proposal.Validate(); err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
		}
		if h.Status == "active" {
			if err = m.checkRealm(tx, h.Proposal, id); err != nil {
				return err
			}
			if err = checkNames(tx, h.Proposal, id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func inventoryRevision(tx *sql.Tx) (string, error) {
	var instance string
	var revision uint64
	err := tx.QueryRow("SELECT instance,revision FROM state WHERE singleton=1").Scan(&instance, &revision)
	return fmt.Sprintf("managed:%s:%d", instance, revision), storageError(err)
}

// saveHost replaces the typed record and its collections inside the caller's
// transaction. Null flags preserve null versus empty collections across reads.
func saveHost(tx *sql.Tx, h *HostRecord, create bool) error {
	p := h.Proposal
	fields := []any{h.Revision, h.Status, p.PrincipalMode, p.Realm, p.Pattern, p.Labels == nil, p.Accounts == nil, h.CreatedAt.UTC().Format(time.RFC3339Nano), h.UpdatedAt.UTC().Format(time.RFC3339Nano), h.ID}
	var err error
	if create {
		_, err = tx.Exec("INSERT INTO hosts (revision,status,principal_mode,realm,pattern,labels_null,accounts_null,created,updated,id) VALUES (?,?,?,?,?,?,?,?,?,?)", fields...)
	} else {
		_, err = tx.Exec("UPDATE hosts SET revision=?,status=?,principal_mode=?,realm=?,pattern=?,labels_null=?,accounts_null=?,created=?,updated=? WHERE id=?", fields...)
	}
	if err != nil {
		return storageError(err)
	}
	for _, table := range []string{"names", "labels", "accounts"} {
		if _, err = tx.Exec("DELETE FROM "+table+" WHERE host_id=?", h.ID); err != nil {
			return storageError(err)
		}
	}
	for _, name := range p.Names {
		if _, err = tx.Exec("INSERT INTO names VALUES (?,?)", h.ID, name); err != nil {
			return storageError(err)
		}
	}
	for name, value := range p.Labels {
		if _, err = tx.Exec("INSERT INTO labels VALUES (?,?,?)", h.ID, name, value); err != nil {
			return storageError(err)
		}
	}
	for i, name := range p.Accounts {
		if _, err = tx.Exec("INSERT INTO accounts VALUES (?,?,?)", h.ID, i, name); err != nil {
			return storageError(err)
		}
	}
	return nil
}

// finish commits the mutation, audit, and inventory revision together. Removal
// keeps the existing contract: cascading deletion also removes the host's audit.
func finish(tx *sql.Tx, id, actor, action string) error {
	if action != "remove" {
		if _, err := tx.Exec("INSERT INTO audit (host_id,time,actor,action) VALUES (?,?,?,?)", id, time.Now().UTC().Format(time.RFC3339Nano), actor, action); err != nil {
			return storageError(err)
		}
	}
	if _, err := tx.Exec("UPDATE state SET revision=revision+1 WHERE singleton=1"); err != nil {
		return storageError(err)
	}
	return storageError(tx.Commit())
}

// checkNames only considers active hosts. An immediate write transaction spans
// the check and mutation, preventing duplicate admissions across connections.
func checkNames(tx *sql.Tx, p Proposal, except string) error {
	if p.Pattern != "" {
		var owner string
		err := tx.QueryRow("SELECT id FROM hosts WHERE pattern=? AND status='active' AND id<>? LIMIT 1", p.Pattern, except).Scan(&owner)
		if err == nil {
			return fmt.Errorf("%w: pattern %s is active on record %s", ErrConflict, p.Pattern, owner)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return storageError(err)
		}
	}
	for _, name := range p.Names {
		var owner string
		err := tx.QueryRow("SELECT host_id FROM names JOIN hosts ON hosts.id=names.host_id WHERE name=? AND status='active' AND host_id<>? LIMIT 1", name, except).Scan(&owner)
		if err == nil {
			return fmt.Errorf("%w: name %s is active on host %s", ErrConflict, name, owner)
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
func (m *Managed) AddPattern(actor string, p Proposal) (*HostRecord, error) {
	if p.Pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	tx, err := m.db.Begin()
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	if err = m.conflict(tx, p, ""); err != nil {
		return nil, err
	}
	id, err := m.unusedID(tx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	h := &HostRecord{ID: id, Revision: 1, Status: "active", Proposal: p, CreatedAt: now, UpdatedAt: now}
	if err = saveHost(tx, h, true); err != nil {
		return nil, err
	}
	h, err = readHost(tx, id)
	if err != nil {
		return nil, err
	}
	if err = finish(tx, id, actor, "add-pattern"); err != nil {
		return nil, err
	}
	return h, nil
}

func (m *Managed) conflict(tx *sql.Tx, p Proposal, except string) error {
	if err := m.checkRealm(tx, p, except); err != nil {
		return err
	}
	return checkNames(tx, p, except)
}

// checkRealm preserves per-host identity for generated realms and identical
// authorization attributes for shared named realms. Realm names are attributes
// of records; there is no separate registry or declaration step.
func (m *Managed) checkRealm(tx *sql.Tx, p Proposal, except string) error {
	realm := principal.Realm(p.Realm)
	if realm == "" {
		return nil
	}
	rows, err := tx.Query("SELECT id FROM hosts WHERE status='active' AND realm=? AND id<>? ORDER BY id", p.Realm, except)
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
			return fmt.Errorf("%w: principal realm is already active on host %s", ErrConflict, id)
		}
		member, err := readHost(tx, id)
		if err != nil {
			return err
		}
		if !sameAuthorization(member.Proposal.Labels, member.Proposal.Accounts, p.Labels, p.Accounts) {
			return fmt.Errorf("%w: realm %q has different authorization attributes from host %s", ErrConflict, realm, id)
		}
	}
	return nil
}

func (m *Managed) unusedID(tx *sql.Tx) (string, error) {
	for {
		id, err := m.newID()
		if err != nil {
			return "", err
		}
		var exists bool
		if err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM hosts WHERE id=?)", id).Scan(&exists); err != nil {
			return "", storageError(err)
		}
		if !exists {
			return id, nil
		}
	}
}

func (m *Managed) Enroll(p Proposal, token string) (*HostRecord, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	tx, err := m.db.Begin()
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	h := &HostRecord{Revision: 1, Status: "pending", Proposal: p, CreatedAt: now, UpdatedAt: now}
	if token != "" {
		if !validID(token) {
			return nil, ErrToken
		}
		reserved, err := readHost(tx, token)
		if errors.Is(err, ErrNotFound) {
			return nil, ErrToken
		}
		if err != nil {
			return nil, err
		}
		t, err := readToken(tx, token)
		if err != nil {
			return nil, err
		}
		if reserved.Status != "pending" || t == nil || t.Revoked || t.UsedBy != "" || !now.Before(t.ExpiresAt) {
			return nil, ErrToken
		}
		if err = m.conflict(tx, p, ""); err != nil {
			return nil, err
		}
		h.ID, h.Status, h.CreatedAt, h.Revision = token, "active", reserved.CreatedAt, reserved.Revision+1
		if _, err = tx.Exec("UPDATE tokens SET used=1 WHERE host_id=?", token); err != nil {
			return nil, storageError(err)
		}
	} else {
		var pending int
		if err = tx.QueryRow("SELECT count(*) FROM hosts WHERE status='pending'").Scan(&pending); err != nil {
			return nil, storageError(err)
		}
		if pending >= 1000 {
			return nil, fmt.Errorf("pending enrollment queue is full")
		}
		if h.ID, err = m.unusedID(tx); err != nil {
			return nil, err
		}
	}
	if err = saveHost(tx, h, token == ""); err != nil {
		return nil, err
	}
	// Read back detached collections before committing; callers never share the
	// slices or maps passed in their proposal with the returned snapshot.
	h, err = readHost(tx, h.ID)
	if err != nil {
		return nil, err
	}
	if err = finish(tx, h.ID, "host", "enroll"); err != nil {
		return nil, err
	}
	return h, nil
}

func (m *Managed) Change(actor, action, id string, revision uint64, p *Proposal) (*HostRecord, error) {
	if p != nil {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	tx, err := m.db.Begin()
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	h, err := readHost(tx, id)
	if err != nil {
		return nil, err
	}
	if revision == 0 || h.Revision != revision {
		return nil, ErrRevision
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
			if err = m.conflict(tx, *p, id); err != nil {
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
		if err = m.conflict(tx, h.Proposal, id); err != nil {
			return nil, err
		}
		h.Status = "active"
	case "deny":
		if h.Status != "pending" {
			return nil, fmt.Errorf("only pending records can be denied")
		}
		h.Status = "denied"
	case "remove":
		if _, err = tx.Exec("DELETE FROM hosts WHERE id=?", id); err != nil {
			return nil, storageError(err)
		}
		return nil, finish(tx, id, actor, action)
	default:
		return nil, fmt.Errorf("unknown inventory action")
	}
	if h.Status != "pending" {
		if _, err = tx.Exec("UPDATE tokens SET revoked=1 WHERE host_id=? AND used=0", id); err != nil {
			return nil, storageError(err)
		}
	}
	h.Revision++
	h.UpdatedAt = time.Now().UTC()
	if err = saveHost(tx, h, false); err != nil {
		return nil, err
	}
	h, err = readHost(tx, id)
	if err != nil {
		return nil, err
	}
	if err = finish(tx, id, actor, action); err != nil {
		return nil, err
	}
	return h, nil
}

func (m *Managed) Get(id string) (*HostRecord, error) {
	tx, err := m.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	h, err := readHost(tx, id)
	if err != nil {
		return nil, err
	}
	return h, storageError(tx.Commit())
}

func (m *Managed) List() ([]HostRecord, error) {
	tx, err := m.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(err)
	}
	defer tx.Rollback()
	ids, err := hostIDs(tx)
	if err != nil {
		return nil, storageError(err)
	}
	hosts := []HostRecord{}
	for _, id := range ids {
		h, err := readHost(tx, id)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, *h)
	}
	return hosts, storageError(tx.Commit())
}

func (m *Managed) CreateToken(actor string, lifetime time.Duration) (EnrollmentToken, error) {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return EnrollmentToken{}, fmt.Errorf("token lifetime must be positive and no more than 24h")
	}
	tx, err := m.db.Begin()
	if err != nil {
		return EnrollmentToken{}, storageError(err)
	}
	defer tx.Rollback()
	id, err := m.unusedID(tx)
	if err != nil {
		return EnrollmentToken{}, err
	}
	now := time.Now().UTC()
	token := EnrollmentToken{ID: id, ExpiresAt: now.Add(lifetime)}
	h := &HostRecord{ID: id, Revision: 1, Status: "pending", CreatedAt: now, UpdatedAt: now}
	if err = saveHost(tx, h, true); err != nil {
		return EnrollmentToken{}, err
	}
	if _, err = tx.Exec("INSERT INTO tokens VALUES (?,?,0,0)", id, token.ExpiresAt.Format(time.RFC3339Nano)); err != nil {
		return EnrollmentToken{}, storageError(err)
	}
	return token, finish(tx, id, actor, "token-create")
}

func (m *Managed) Tokens() ([]EnrollmentToken, error) {
	rows, err := m.db.Query("SELECT host_id,expires,used,revoked FROM tokens ORDER BY host_id")
	if err != nil {
		return nil, storageError(err)
	}
	defer rows.Close()
	tokens := []EnrollmentToken{}
	for rows.Next() {
		var t EnrollmentToken
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

func (m *Managed) RevokeToken(actor, id string) error {
	tx, err := m.db.Begin()
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	t, err := readToken(tx, id)
	if err != nil {
		return err
	}
	if t == nil {
		return ErrNotFound
	}
	if _, err = tx.Exec("UPDATE tokens SET revoked=1 WHERE host_id=?", id); err != nil {
		return storageError(err)
	}
	if _, err = tx.Exec("UPDATE hosts SET revision=revision+1,updated=? WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
		return storageError(err)
	}
	return finish(tx, id, actor, "token-revoke")
}

func (m *Managed) Audit() ([]AuditEvent, error) {
	rows, err := m.db.Query("SELECT time,actor,action,host_id FROM audit ORDER BY sequence")
	if err != nil {
		return nil, storageError(err)
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var at string
		if err = rows.Scan(&at, &e.Actor, &e.Action, &e.Resource); err != nil {
			return nil, storageError(err)
		}
		if e.At, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return nil, storageError(err)
		}
		events = append(events, e)
	}
	slices.SortStableFunc(events, func(a, b AuditEvent) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		return strings.Compare(a.Resource, b.Resource)
	})
	return events, storageError(rows.Err())
}

// LookupHost reads current host facts and the inventory revision in the same
// snapshot. Exact names take precedence over active pattern records.
func (m *Managed) LookupHost(ctx context.Context, name string) (*ResolvedHost, string, error) {
	name = hostpattern.NormalizeName(name)
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", storageError(err)
	}
	defer tx.Rollback()
	revision, err := inventoryRevision(tx)
	if err != nil {
		return nil, "", err
	}
	var id string
	err = tx.QueryRow("SELECT host_id FROM names JOIN hosts ON hosts.id=names.host_id WHERE name=? AND status='active'", name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		rows, queryErr := tx.Query("SELECT id,pattern FROM hosts WHERE status='active' AND pattern<>'' ORDER BY id")
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
					queryErr = fmt.Errorf("%w: hostname %s matches pattern records %s and %s", ErrConflict, name, id, candidate)
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
	h, err := readHost(tx, id)
	if err != nil {
		return nil, "", err
	}
	p := h.Proposal
	if p.Pattern != "" {
		p.Names = []string{name}
	}
	resolved := &ResolvedHost{Policy: Host{Names: p.Names, Labels: p.Labels, Accounts: p.Accounts}, PrincipalMode: p.PrincipalMode, Realm: principal.Realm(p.Realm)}
	return resolved, revision, storageError(tx.Commit())
}
