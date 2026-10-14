# Directory facts and SCIM groups

The directory maps its source data into Writ's user and membership objects.
`User` and `Group` describe authorization facts. `ManagedUser` and `ManagedGroup`
describe the control-plane records used by storage and SCIM. `User.Facts` maps
the directory's data-plane types into Writ objects.
Users need an authentication ID. On SCIM creation, Epithet selects a configured
attribute and assigns its value to the user's `id` before calling storage.
That same ID addresses the SCIM resource and the authentication lookup. Storage
preserves the supplied ID and does not interpret `externalId` or OIDC claims.
Inactive users are absent from the authorization lookup. Administration can
still inspect inactive users.

Each group membership contains the group's current display name and SCIM resource
ID. An optional group `externalId` is exposed as an additional attribute. Group
names need not be unique. `group:ops` matches members of any current group named
`ops`; `group{id:...}` follows one resource across renames. Once a rename is
visible, its new name replaces the old name. Deleting and recreating a group
under the same name makes name-based rules follow the replacement; ID-based
rules do not follow it.

There are no historical group-name bindings. `epithet directory groups list`
lists current names and resource IDs through paginated SCIM;
`epithet directory groups audit` retains provisioning history and historical binding events. The bind command is removed.
Existing administrator group grants also match current names.

Static YAML supplies structured memberships without requiring group IDs:

```yaml
users:
  - id: oidc-subject
    userName: alice
    name: [alice, alice@example.com]
    attributes:
      department: engineering
      role: [developer, oncall]
    groups:
      - name: [operators]
        attributes:
          environment: production
```

Omitting `name` uses `userName` as the selectable name when present. An explicit
empty name collection supplies no selectable names. `userName` remains certificate
presentation, with ID fallback. Additional attributes must be strings, collections
of strings, or null, and cannot replace the defined `name` or `id` fields.

See the [fact API contract](../../../docs/fact-services.md) for the HTTP shape and
[Writ specification](../../../writ/SPEC.md) for matching rules.

## SCIM identity configuration

Set `scim-user-id-attribute` in TOML or use `epithet directory
--scim-user-id-attribute ATTRIBUTE`. The default is `externalId`. The setting is
read by the directory process, including when launched by `epithet server` with
the shared configuration file. It does not change the OIDC claim selection;
configure `oidc-user-id-claim` so its value matches the selected SCIM attribute.

For example, an Entra integration can send `objectId` as SCIM `externalId` and use:

```toml
scim-user-id-attribute = "externalId"
oidc-user-id-claim = "oid"
```

The adapter supports the string attributes it stores: `externalId`, `userName`,
`userType`, `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department`,
and `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization`.
Attribute names are case-insensitive; identity values are exact. Unsupported
attributes, including the incoming read-only `id`, are configuration errors.
A missing or blank selected value fails creation; there is no fallback to another
attribute. This does not add arbitrary extension-attribute storage.

Choose a value that is unique, stable and never reassigned to another resource.
The configured attribute is used only at creation: subsequent operations use
the URL ID, which remains unchanged even if the source attribute is replaced or
omitted. Changing this setting does not remap existing users. The store treats
`externalId` as optional data without a uniqueness constraint.

Go service implementors configure the adapter with
`factserver.WithSCIMUserIDAttribute(attribute)` alongside
`factserver.WithDirectoryManagement(store)`. Direct `Store.CreateUser` callers
must supply the resolved `ManagedUser.ID` themselves. Storage returns the
updated object with that ID and the caller-supplied Created and Modified
timestamps. Storage assigns Version. The SCIM adapter sets both timestamps on
creation and Modified on replacement. Storage retains the original Created on
replacement. DeleteUser takes an explicit modification time for the groups whose
memberships it removes.
Replacement selects the resource by the supplied object's ID, with no separate ID
argument. The SCIM adapter sets that ID from the request URL.

Epithet generates group IDs before calling storage. Direct `Store.CreateGroup`
callers supply their own ID; storage preserves it and rejects collisions with
existing user or group IDs.

Before a direct store write, call `user.Validate()` or `group.Validate()` and
handle its error. Validation rejects blank required fields without changing the
record. The SCIM adapter validates automatically before writes. Storage receives
the actual attributes and enforces ID uniqueness, username uniqueness, membership
references and existence. Username uniqueness uses Unicode NFKC normalization followed by case folding, while preserving the
supplied spelling. Derived comparison keys and indexes are private to each backend;
callers do not supply or maintain them.

Callers also deduplicate `ManagedGroup.MemberIDs` before creation or replacement.
The SCIM adapter does this when converting the request into a managed group;
storage implementations need not normalize duplicate input.

`Store.SupportsPatchUser()` and `Store.SupportsPatchGroup()` declare partial-update
support separately for users and groups. These are stable backend capabilities,
not per-request authorization checks. SCIM advertises `patch.supported` when
either is true and returns a SCIM `501 Not Implemented` error for PATCH requests
against an unsupported resource type. Both current backends return false;
the patch operations themselves are not implemented yet.

`LookupUser` returns only the user and an error; directory implementations do not
need a global revision. Audit events also have no directory revision. Epithet
constructs each event before calling a mutation, supplying its actor, action,
resource ID and timestamp. Storage preserves the event unchanged. SQLite writes the event in the same transaction as the mutation;
other backends retain their own consistency semantics. Audit history survives
resource deletion.

`Audit(ctx, cursor, limit)` returns events and an opaque continuation cursor.
Empty cursor starts a read; pass the returned cursor back unchanged. Empty next
means no further page. Ordering, visibility during writes, and cursor lifetime
belong to the backend. Timestamps need not be unique or monotonic. HTTP and CLI
pages contain `events` and an optional `next`; use `--cursor` to continue.

## Testing a directory backend

Use `directory/storetest.Run` to check an implementation of `Directory` and
`Store` without starting an HTTP server. In your backend's test package:

```go
func TestStoreContract(t *testing.T) {
    storetest.Run(t, func(t *testing.T) storetest.Backend {
        store := newMemoryDirectory() // Your constructor; initialize fresh state.
        backend := storetest.Backend{Directory: store, Store: store}
        return backend
    })
}
```

Import `testing` and
`github.com/epithet-ssh/epithet/pkg/facts/directory/storetest`. The factory runs
for each subtest and must return a fresh, empty directory. These sequential
examples expect completed writes to be readable in the test fixture. For a backend
with delayed visibility, the factory can supply a test view that waits for its
own propagation. This fixture assumption is not a consistency requirement for
the storage interface. Register cleanup with `t.Cleanup`; see
[SQLite's factory](sqlitestore/contract_test.go).

The directory interfaces describe complete operations without requiring
transactions, concurrent access, immediate read-after-write visibility, or coherent
snapshots across resources, memberships and audit history. Those
properties belong to each backend. A failed call does not establish whether a
write took effect.

Resource versioning is optional. `SupportsVersioning()` declares support for
users and groups. Providers that return false leave `Metadata.Version` empty;
callers pass an empty `expectedVersion`.
Providers that return true assign nonempty opaque versions and change them on
mutations, including membership cleanup. The in-memory example supports versioning.

SCIM advertises this capability as `etag.supported`. With versioning, the adapter
returns the token as both an ETag header and `meta.version`, and translates a
client's `If-Match` header into `expectedVersion`. Without versioning, both response
fields are omitted. A specific ETag cannot match an unversioned resource and
receives 412; requests without a version condition remain available. Replacement
metadata does not supply the version condition.

SQLite supports versioning and compares versions atomically with writes. Its
transactional mutations and coherent reads are SQLite properties, tested in
`sqlitestore`, rather than requirements for other backends.

Run `go test -v ./path/to/your/backend`. The shared suite exercises sequential
user and group lifecycle, authorization projections, pagination
and audit. It does not establish transactionality, concurrency safety, or
propagation timing. Test any stronger backend guarantees separately, along with
persistence, failure handling and HTTP behavior.

## Database upgrade

The application creates new databases directly at schema version 4, without an
`aliases` table or uniqueness constraint on user `externalId`. Audit rows contain
timestamps and event fields, without sequence or revision columns. It opens version 4
databases normally and rejects other schema
versions without upgrading them. `PRAGMA user_version` identifies the schema the
binary understands; the application does not manage migrations.

Version 2 stored separately generated user IDs and looked up users by
`externalId`. Simply changing its version marker would not convert those
identities or their membership references. This change supplies no database
conversion tool; an existing deployment needs a separately planned conversion.

A supported migration framework, potentially Goose, is deferred in
[YATL gt3vjk35](../../../.tasks/open/gt3vjk35.md). No framework or automatic upgrade
path is introduced by this change.
