# ADR 0002: Discover fact-service management and share inventory implementation

- Date: 2026-10-14
- Status: Accepted.
- Scope: Inventory and SCIM provider management, authentication, and backend ownership.

## Context

Directory management has an industry-standard API in SCIMv2. Host inventory needs
our own contract. Both belong behind control, where public authentication and
administrative grants already live. Alternative inventory fact providers must
remain usable even when they implement only authorization lookups.

The built-in inventory API used an action-dispatch envelope at a fixed `/manage`
path. That required other providers to copy both that protocol and inventory
implementation details. We expect to publish a bundled SQLite service and
separate Firebase and DynamoDB services. Their database mechanics differ; their
HTTP protocol and inventory rules should not.

## Decision

Use resource-oriented HTTP for the inventory provider API. Discover its records,
tokens and audit locations through RFC 9652 Link-Template headers on OPTIONS at
the configured, complete inventory fact URL. Expand RFC 6570 templates and then
resolve relative references. The CLI knows the operations; discovery supplies
locations and variable slots rather than a method catalogue. Do not recursively
send OPTIONS to discovered resources.

Any 4xx on initial OPTIONS means no management support: retain data-plane lookup
use. A successful response without inventory relations has the same meaning.
Transport failures, 5xx, redirects and malformed or partial advertisements are
errors. This fallback never applies to failed management operations.

Provide only methods used by the CLI: list/create/read/replace/delete records,
create/revoke enrollment tokens, and read audit pages. There are no token reads,
PATCH operations, bulk actions or separate approval resources. Whole-record PUT
uses the existing record revision as a strong ETag with If-Match. The service
signature covers If-Match along with method, target, body and actor. Edit and
review remain separate operations; PUT cannot combine a proposal change with a
status transition. Server-owned identity and timestamps must be echoed unchanged.

Enrollment PUT targets the client-selected host ID and carries a host and optional enrollment credential. Status derives
from authority: enrollment authenticated by control's shared enrollment bearer creates pending state;
a valid single-use credential becomes the host ID and is consumed while creating the active host; an authorized admin can
create an active pattern. A pattern alone never conveys administrative authority.
Existing lifecycle, name constraints and deletion semantics remain.

Human CLI administration uses OIDC through the agent and control's inventory-admin
grant. An optional, separately configured inventory shared secret supports
automation. It grants no directory authority and is distinct from single-use
enrollment tokens and the SCIM secret. Providers trust control-signed requests,
not the public credential.

Apply the same provider boundary to SCIM. Signed OPTIONS at the complete directory
fact URL advertises its SCIM base with ordinary Link and relation
`https://epithet.dev/rel/scim`. SCIM defines its own resource addressing, so no
URI template is needed. Initial discovery 4xx means data-only support, just as for
inventory. Control forwards signed SCIM HTTP directly instead of tunneling it in
JSON. Bind Content-Type as well as If-Match so body interpretation and write
preconditions remain protected when removing the envelope.

Control accepts the optional SCIM provisioning secret and OIDC directory-admin
identities. Human identity survives the signed hop into audit; secret provisioning
retains the `scim` actor. Standard SCIM resource references into the discovered
provider base are rebased to control's public path; extension attributes and
external references remain untouched. The reusable directory HTTP adapter owns
SCIM protocol handling, and directory stores implement complete operations and
persist audit history. Directory consistency guarantees are backend-specific
(see the amendment below).
Directory CLI design remains deferred in YATL `ywxp1g89`. Existing built-in actor,
listing and audit endpoints remain separate; this change does not redesign them.

Keep data and management interfaces independent: `directory.Directory` and
`inventory.Hosts` provide lookups; their respective `Store` interfaces provide
management. Each service constructor requires data and accepts a typed optional
management implementation (`WithDirectoryManagement` or `WithInventoryManagement`).
One instance may fill both roles, or implementors may supply separate instances
for the same logical service. Management is never inferred from the data source's
method set. Lifecycle remains with the executable.

The reusable inventory handler owns authentication, discovery, JSON, routes,
ETags and errors. Shared inventory
functions own validation and state-transition rules. Backends own queries,
transactions and conditional writes, enforcing complete mutations atomically.
The executable owns the store's lifetime. The common implementation has no cloud
SDK dependency. A shared store contract suite tests multiple handles against the
same database, including concurrent approval and single-use redemption.

## Alternatives and tradeoffs

Separate managed constructors would also work. Typed options retain one entry
point per fact service while making the additional control plane explicit. They
accept an independent management interface, rather than requiring management on
the data instance or discovering it with runtime type assertions.

Keeping the action envelope would preserve the existing dispatch code, but would
retain fixed routing and a second operation vocabulary for every provider. REST
uses familiar methods and preconditions. The internal CLI/control envelope can
continue adapting commands without becoming the provider contract.

Hard-coded resource paths would be simpler for the built-in service but impose
its routing on external providers. Ordinary Link fields do not describe member
and query-variable expansion. Link-Template makes those details provider-owned
without adding search or lookup APIs just to discover resource URLs.

Keeping the SCIM JSON tunnel would be a smaller local change but require every
external provider to implement a second protocol. Moving SCIM into control and
inventing generic directory CRUD would duplicate the standard. Direct SCIM HTTP
keeps the provider contract familiar; its cost is rebasing standard resource URLs
at the public boundary. A shared Link parser serves both CA and SCIM discovery.

A generic storage/transaction interface beneath one shared engine would centralize
more execution code, but risks becoming a database portability framework.
Firestore-style transaction callbacks and DynamoDB conditional batches differ.
Complete domain operations hide those differences; shared pure rules and contract
tests reduce duplication. Refine signatures through actual cloud implementations.
The Firebase storage product is not selected by this decision.

Whole-record PUT makes the reviewed state explicit and reuses existing revision
checks. List results omit per-record versions, so selection requires an item GET
before review. Pagination retains bounded record-ID and backend-cursor continuation without adding
cross-page snapshot semantics. The SQLite schema remains unchanged.

The [inventory package contract](../../pkg/facts/inventory/README.md) documents
wire shapes and adapter responsibilities. YATL `s9cqey45` retains planning and
discussion history; this ADR records the reasons for the design.

## Amendment: directory consistency (2026-10-17)

Keep complete-operation methods at the directory storage boundary. Do not expose
transactions or require all backends to provide transactional mutations,
concurrency control, coherent snapshots or immediate visibility. Eventually
consistent implementations are valid; a failed call need not imply rollback.
Version-precondition enforcement is backend-specific. The bundled SQLite store
retains its stronger behavior and tests it within its own package.

Shared storage tests exercise sequential operations with a fixture that makes
completed writes readable; that fixture assumption does not define propagation
behavior for production backends. Concurrency, version enforcement and rollback
checks belong to the concrete backend's tests. This amendment applies to the
directory; inventory admission and enrollment semantics are unchanged.


### Group listing uses SCIM (2026-10-17)

Remove the separate unpaginated group-summary operation and its GroupSnapshot
wrapper. It duplicated SCIM group listing and required every storage backend to
implement a second enumeration contract. The CLI consumes SCIM group pages via
the agent and control, using the existing ListGroups storage operation. There is
no directory-wide revision attached to a listing. Complete group resources include
memberships, so pagination bounds group count rather than each group's size.

## Amendment: directory audit ownership and global revisions

Epithet constructs audit events above storage and passes each event with its
mutation. Backends preserve the supplied actor, action, resource ID and timestamp,
preserving every supplied field. This allows SQLite to persist both in one
transaction without requiring transactions from every implementation.

Directory lookup returns the user and an error, without a directory-wide revision.
Audit events likewise have no global revision or sequence. Pagination uses
backend-owned opaque cursors, separate from events. A global snapshot identifier imposes coordination on backends
without serving a required behavior. Per-resource versions remain a separate
contract; SQLite's internal version counter is an implementation detail.

## Amendment: optional directory resource versions

Resource versions support SCIM's optional ETag and If-Match behavior, but are not
required from every storage provider. Store.SupportsVersioning declares the
capability for users and groups. Providers without it return empty versions;
SCIM omits ETag and meta.version and advertises etag.supported=false. SQLite
retains conditional writes, and the in-memory example retains its resource versions.

A capability method lets discovery describe support before any resource exists;
inferring support from one resource's version would not do that. Epithet serves
ServiceProviderConfig because the pinned SCIM library hardcodes ETag support to
false. Per-resource versions remain independent of global directory revisions.

## Amendment: inventory audit ownership and retention

Epithet generates inventory resource IDs before storage and supplies complete
audit events with every mutation. A single-use credential becomes the enrolled host ID; token creation stores no host.
The storage adapter preserves every field of the supplied event and may
commit it with the mutation. This follows directory's ownership model and avoids
making adapters infer the actor, action, resource ID or operation time.

Resource deletion retains audit history and records removal. SQLite schema
version 2 removes the cascading foreign key from audit to hosts; older schemas
are rejected without automatic migration. List and Audit keep their existing
cursor pagination, now covered by the shared backend contract tests.

## Amendment: audit timestamps and backend-owned continuation

Directory and inventory audit events contain timestamps, without global sequence
numbers or an ordering requirement. Audit reads take an opaque string cursor and
return events plus the next cursor. Epithet forwards cursors unchanged. Empty input
starts a read; empty next means no further page. Ordering, concurrent-write
visibility, and cursor lifetime remain backend properties.

The SQLite adapters use private row positions for continuation. The in-memory
directory uses slice positions. Neither representation appears on audit events.
This avoids pretending timestamps are unique, monotonic, or sufficient to resume
bounded pages. Directory schema 4 and inventory schema 2 omit audit sequence
columns; their resource-version mechanisms remain separate.

### Inventory lookup revisions removed (2026-10-17)

Inventory lookup returns host facts and an error, without global revision
metadata. The revision served only issuance logging and imposed a global counter
on storage with no authorization or conditional-write benefit. SQLite schema 3
removes the global state table. Inventory responses and CA issuance logs no longer
carry this metadata; per-resource revisions used for conditional writes remain.

### Realm sharing imposes no cross-record constraints (2026-10-17)

Realm sharing does not require matching labels or account restrictions. Generated
realms also have no uniqueness constraint across hosts; random generation supplies
collision resistance without an inventory-wide check. Exact hosts and patterns
may use the same realm while retaining independent authorization facts. Removed
the cross-record realm scans, equality checks, and generated-realm pattern ban.

### Exact and wildcard names share one host model (2026-10-17)

`Host` carries names, authorization facts, and enrollment metadata. Its names may
be exact hostnames or wildcard expressions. The nested `Proposal` and domain
`HostRecord` types are removed. A separate `Pattern` type and parallel storage
operations were considered, but name syntax already identifies the distinction;
they would duplicate the model and management interface.

Storage owns indexing rather than exposing a separate resource kind. SQLite
schema 4 indexes the exact/wildcard classification per name. Lookup checks active
exact names first, then considers only wildcard names. Multiple matching names
on one record supply the same facts; matching different records remains an
ambiguity error. Wildcard lookup returns a host with the requested concrete name.

Enrollment accepts exact names. Administrator creation accepts exact and wildcard
names through the same host model and the `inventory add` command. Read, list,
edit, and removal operations are shared. The provider and control API payloads
use their existing name arrays for wildcard expressions too; the separate
`pattern` field is removed.


### Pending enrollment requires a scoped bearer credential (2026-10-18)

Anonymous pending submissions expose storage and administrator attention to
unsolicited enrollment. Control therefore requires a configured shared bearer
credential for this operation. It authorizes submission only; activation still
requires administrator approval. No configured credential means no pending
submissions. Single-use preapproval credentials retain their separate path.

Control is the sole owner of this authentication check. The bearer is never
forwarded to inventory or stored with the host. Providers continue accepting
control-signed enrollment requests. Control explicitly rejects the enrollment
bearer for inventory administration and SCIM, without falling through to OIDC or
other shared-credential authorization.


### Optional opaque inventory resource versions (2026-10-18)

Inventory versions express a concurrency precondition, not a numeric sequence.
`Host.Version` is a string; mutation methods receive `expectedVersion string`.
The backend owns version generation and callers only compare tokens for equality.
SQLite retains its internal counter without exposing arithmetic in the contract.

Like directory, inventory stores declare `SupportsVersioning()`. Unsupported
stores return empty versions and receive empty preconditions. Empty
`expectedVersion` requests no check; enforcement and atomicity belong to the
backend. The built-in HTTP adapter emits ETag and requires If-Match only for
versioned stores. Control and CLI preserve opaque versions and omit preconditions
for providers whose responses have no ETag.


## Amendment: retryable enrollment PUT

Both enrollment paths use PUT to a stable host ID. The client stores that ID in
`id` beside the default `realm` file and CA public key before its first request.
The ID is generated for pending enrollment or taken from the single-use token.
Control confines the shared enrollment bearer to pending submissions and never
forwards it to inventory. `EnrollHost` performs creation and any token consumption
in one storage call; SQLite commits them with the caller-supplied audit event.
Identical retries return the existing host without mutation; differing facts
cannot replace it. Administrative review remains separate. SQLite schema 5 removes
the token-to-host foreign key because unused tokens no longer create reservations.
