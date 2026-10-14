---
yatl_version: 1
title: Design SCIM directory management and CLI access through control
id: ywxp1g89
created: 2026-10-13T15:43:29.263132Z
updated: 2026-10-17T18:04:17Z
author: Brian McCallister
priority: low
tags:
- design
- control
- directory
- scim
---

# SCIM directory management and CLI access

SCIM exposure through control was authorized on 2026-10-14 and is implemented.
User and group listing now use paginated SCIM through the agent and control; lookup-only
directories cannot enumerate users or groups. Manual directory user creation/editing on the CLI remains deferred, lower-priority
work split from inventory task `s9cqey45`.

## Implemented SCIM provider boundary

- Signed OPTIONS at the complete directory fact endpoint discovers a SCIM base
  using `Link: </scim/v2/>; rel="https://epithet.dev/rel/scim"`. Ordinary Link was
  explicitly chosen because SCIM already defines resource paths and query syntax.
- Initial discovery 4xx or successful discovery without the relation means
  data-only support. Transport errors, 5xx, redirects and invalid target URLs
  remain failures. There is no recursive OPTIONS discovery or capability cache.
- Forward SCIM HTTP directly with signed method, target, body, actor, If-Match and
  Content-Type. Removed the private POST `/scim` envelope. The public route stays
  `/scim/v2/`. Preserve statuses, ETags, query encoding, and response bodies.
- Rebase standard resource references (Location, meta.location, User groups.$ref,
  Group members.$ref, including list results) from the private SCIM tree to the
  public path, as explicitly agreed. Preserve external references and extensions.
- The provisioning secret is optional. OIDC directory-admin users can access SCIM
  without it. Control authenticates and authorizes; providers trust control-signed
  requests and preserve human identity in audit. Secret provisioning uses `scim`.
- HTTP directory URLs on CA/control now name the complete fact endpoint, just like
  inventory URLs. Unix socket URLs retain /lookup. `directory-backend` remains
  the built-in root for actor snapshots and audit, separate from SCIM.
- The original control exposure preserved the SCIM subset and storage. Identity
  ownership was subsequently revised as recorded below. Additional directory CLI
  commands remain deferred.

## Agreed direction

- SCIMv2 is the directory-management API, including user/group listing. Do not
  introduce a parallel user/group management API.
- Control fronts SCIM. The existing provisioning token becomes an optional shared
  secret; OIDC users with directory-admin grants can invoke the same operations.
  Omitting the secret disables that authentication path, not authorized OIDC access.
- CLI access uses OIDC through the existing agent. Control authenticates private
  provider requests and preserves human actor identity.
- Commands belong under `epithet directory`, not `control` or `scim`.
- Accept names when unique, rejecting absent or ambiguous matches. Retain explicit
  ID addressing. Do not put Writ selectors/filter expressions on the CLI.
- Keep the built-in directory's single SCIM `userName`, projected to fact `name`
  as `[userName]`. Do not expand storage to multivalued names; other providers
  may still supply multiple names through the general fact API.
- Proposed creation shape discussed and accepted:
  `epithet directory users create NAME [--id ID]`. NAME supplies `userName`;
  `--id` supplies authentication identity via SCIM `externalId`, defaulting to NAME.
  Identity assignment was subsequently revised below; the store no longer
  generates a separate user ID.

## Identity mapping ownership

The agreed user identity is now assigned by Epithet's SCIM adapter before calling
storage. `CreateUser` requires and preserves `ManagedUser.ID`; storage assigns
only Version, preserving caller-supplied Created and Modified timestamps.
The SCIM adapter sets both on creation and Modified on replacement. Storage
retains the original Created on replacement. DeleteUser takes an explicit
modification time for affected groups during membership cleanup.
`GetUser` and `LookupUser` use the same ID. User
`externalId` is optional and is not independently unique. Replacement uses the
URL resource ID and cannot change it by changing the source attribute.
ReplaceUser and ReplaceGroup take the replacement object and expectedVersion;
the object ID selects the record. The SCIM adapter assigns it from the URL,
avoiding duplicate identity arguments at the storage boundary.
Group creation now follows the same ownership boundary: Epithet generates the
SCIM group ID before calling CreateGroup, and storage preserves the supplied ID.
Group validation requires it; duplicate IDs return ErrConflict.

Audited group operations against the user contracts: supplied IDs, validation,
full replacement, opaque version checks, absent reads and directory errors align.
Group names and external IDs remain nonunique. Extended group metadata and
SQLite-specific concurrent-write tests.

`scim-user-id-attribute` configures the adapter's source field, defaulting to
`externalId`; it is independent of OIDC claim selection. The current selector
accepts the string attributes already retained by the adapter and rejects
unsupported attributes. No provider detection or arbitrary attribute persistence
is added. See the directory README for configuration and
[provider research](../../docs/oidc-scim-identity-mapping.md) for matching claims.

SQLite schema version 3 removes externalId uniqueness. Older schemas are rejected
without modification; this change does not provide a conversion tool. The
user-owned in-memory implementation remains for the user to adapt to the updated
contract.

Validation: `make -B build` and race tests for `pkg/facts/directory/...` and
`pkg/broker` passed. `make test` passed all production and integration packages;
the unfinished `examples/facts/inmemory` implementation failed its contract tests,
including preservation of the supplied ID. It was not modified.

## Input validation and storage constraints

ManagedUser.Validate and Group.Validate own record-only validation before storage,
without changing attributes. SCIM invokes validation before writes. Store backends
receive actual user/group attributes and handle uniqueness, existence and
membership references. Consistency and version enforcement are backend-specific. Username comparison retains NFKC and
case folding, with derived index keys private to the backend. SQLite computes its
existing name_key internally; ManagedUser has no UserNameKey field. Tests requiring
caller-supplied keys were removed. Existing tests are verification claims, not the
source of requirements; review them against agreed behavior when evaluating the
storage contract.

## Opaque resource versions

Directory resource versions and explicit replace/delete preconditions are opaque
strings. Version enforcement is backend-specific; SQLite compares a nonempty expected
version atomically with the write. Empty means no requested version check. Supplied replacement metadata does not select the
precondition. The SCIM adapter owns ETag encoding and If-Match lists/wildcards;
SQLite retains numeric revisions internally without a schema change. Contract
tests require version changes, not numeric ordering.

## Identity mapping and deferred CLI discussion

Manual creation only works when the chosen ID equals the verified OIDC claim
used for directory lookup. Existing options include stable-id (sub by default,
Entra oid by default), verified-email, and an explicit top-level user-id-claim.
Defaulting ID to NAME is meaningful only when that value matches the configured
mapping. Manual CLI setup still needs discussion; the SCIM mapping setting above
is implemented, but no new enrollment workflow was agreed. An invite flow was explicitly NOT proposed
by the user and is outside this task.

The suggested minimal CLI covers list/show/create/update/delete for users and
groups, plus group add-member/remove-member. This catalogue is still a proposal.
Unique-name lookup is agreed; exact targeting flags remain open. Explicit groups
were recommended, but the group lifecycle discussion was not completed.

The user proposed `-e/--edit` to open a prefilled YAML document shaped like SCIM
core and enterprise-extension attributes, allowing additional attributes.
Template details and additional-attribute preservation/storage remain unresolved.
The earlier repeatable-name and separate-user-name flags were superseded by the
single-name decision. Do not implement arbitrary attribute storage merely because
an editor can accept it.

## Provider boundary and remaining decisions

Authorization fact lookup stays separate from directory management. ADR 0001
removed historical group binding/reconciliation. Group names and identities now
follow the current provider facts. Do not restore binding operations.

Consider whether ordinary user facts suffice for administrator authorization;
removing the separate actor/revision protocol was recommended but not yet agreed.
The current backend no longer checks the authorization revision formerly used
for rebinding. Determine audit inspection separately from standard SCIM operations.

The chosen direct-SCIM transport avoids requiring external providers to implement
an Epithet JSON tunnel. Moving SCIM adaptation into control and inventing generic
directory CRUD was rejected because it duplicates the standard. The signed actor
snapshot and directory audit protocols remain. The
unpaginated ListUserFacts/UserLister contract and directory-users operation were
removed by explicit agreement; user and group enumeration use standard SCIM ListResponse
pages (100 requested per page), consumed incrementally by the CLI. JSON output
is one complete SCIM resource per line. User table output distinguishes resource
id from externalId and shows userName and active; it does not reconstruct group
memberships. No whole-directory revision is promised across pages.

## Design record

The user requested discussion followed by ADR 0002 for the settled management
interface, alternatives and rationale. ADR 0002 now records the settled inventory
and SCIM provider boundaries; deferred directory CLI work must not block either.
Implementation planning and sequencing stay in YATL.

The original combined exploration and conversation log remain in the history of
`s9cqey45`. Its older binding proposals were superseded by ADR 0001 and the SCIM
boundary above.

## Directory consistency boundary

Complete-operation methods remain. The shared directory contract does not require
transactions, concurrency control, coherent snapshots or immediate read visibility.
Eventually consistent backends are valid. Version-precondition enforcement belongs
to the backend, and a failed call need not imply rollback. SQLite retains its
existing implementation and stronger tests. Shared tests exercise sequential
behavior using a fixture whose completed writes are readable; transaction,
concurrency and conditional-write tests are scoped to SQLite. Inventory semantics
and the user-owned in-memory implementation are unchanged.

## Next interface work: incremental membership

Membership input normalization belongs before storage: the SCIM adapter
deduplicates MemberIDs for both group creation and replacement. Direct callers
supply distinct IDs. Shared storage tests no longer require backends to
normalize duplicate input.

Removed the defensive-copy requirement from Store and the shared tests that
mutated input/returned membership slices to demand isolation. Our callers do
not perform those mutations. No replacement immutability requirement was added.

ListUsers/ListGroups use backend-defined traversal order; the contract no longer
requires sorting by resource ID. Shared pagination tests establish that order
from a complete listing and check pages against it. Empty slices may be nil,
including empty pages, membership lists and audit results.

The user approved incremental additions and removals, including SCIM PATCH.
Preserve ordered operations in a complete storage call. Membership predicates
must be evaluated by storage so the adapter need not load the whole group.
Reuse the library's parsed filter AST; do not invent another AST or restrict
valid PATCH expressions to suit the storage interface. HTTP validation remains
in the adapter. This does not add transactional or concurrency guarantees to
the shared Store contract.

Store now declares SupportsPatchUser() and SupportsPatchGroup() separately,
as requested, rather than using optional interfaces. The adapter derives the
service-wide patch.supported flag from these declarations and returns SCIM 501
for unsupported resource types. SQLite and the in-memory example both currently
return false. Actual patch methods and membership delta execution remain pending;
the capability declarations do not implement them.

Capability validation: fresh make build passed. Full make test passed outside
the four existing in-memory contract failures (membership lifecycle, pagination
and detached memberships, audit retention, and group ID collisions). SCIM tests
cover all four capability combinations and protocol rejection/discovery.

---
# Log: 2026-10-13T15:43:29Z Brian McCallister

Created task.

---
# Log: 2026-10-13T15:45:10Z Brian McCallister

Split from s9cqey45 at user request. Preserved agreed SCIM/control authentication, agent-backed CLI direction, unique-name addressing, single-name creation and OIDC mapping discussion. Manual directory administration is deferred; inventory is higher priority. Implementation remains unapproved.

---
# Log: 2026-10-14T09:07:01Z Brian McCallister

Started working.

---
# Log: 2026-10-14T09:13:32Z Brian McCallister

Implemented the authorized SCIM exposure through control: OPTIONS/Link discovery, direct signed SCIM HTTP, optional provisioning secret plus OIDC directory-admin, human audit identity, and standard resource URL rebasing. Complete directory fact URLs align with inventory. Updated ADR 0002 and provider documentation. Full make test passed, including server integration tests; final build/checks recorded separately. Directory CLI design remains deferred.

---
# Log: 2026-10-14T09:13:32Z Brian McCallister

Stopped working.

---
# Log: 2026-10-14T09:14:12Z Brian McCallister

Final verification: make -B build and make test passed (including test/server). Focused facts, SCIM, CA-client and wire suites passed again after final ownership cleanup. Reviewed the SCIM-only diff against the completed inventory snapshot; directory CLI and broader actor/audit protocol redesign remain deferred.

---
# Log: 2026-10-14T09:26:22Z Brian McCallister

Separated the data and management contracts. DirectoryHandler and InventoryHandler now require a data source and accept typed WithDirectoryManagement / WithInventoryManagement options; each pair may use the same instance or independent implementations of one logical service. Store interfaces no longer embed lookup interfaces, and directory Close remains concrete lifecycle ownership. Updated provider docs and ADR 0002; tests cover separate database handles and explicit opt-in.

---
# Log: 2026-10-14T09:27:03Z Brian McCallister

Constructor/interface refactor validation: make -B build and full make test passed. Reviewed the incremental diff; only interface separation, explicit constructor options, caller/test adaptations and related documentation changed. Existing static-directory inspection remains supported.

---
# Log: 2026-10-14T09:38:48Z Brian McCallister

Completed the approved cohesion refactor: SCIM forwarding, OPTIONS discovery and resource URL rebasing are private to facts/control/scim.go; removed the public SCIM client/request/result types. Shared signed HTTP exchanges now live in internal/servicehttp, with the unchanged signing and verification protocol relocated to pkg/serviceauth. Domain statuses and errors remain with their callers. Updated provider imports, documentation and tests; added dependency and discovered-URL policy checks. Reviewed the incremental diff against a5df7604. Final make -B build and make test passed, including server integration tests.

---
# Log: 2026-10-14T10:28:58Z Brian McCallister

Implemented the approved organization audit: private provider operations now belong to control; service constructors and HTTP conversions live with their directory/inventory handlers; inventory models no longer import the administration protocol. Consolidated CLI broker exchanges and CLI-only configuration helpers, made the Writ frontend private within pkg/writ, and merged the small CA/discovery/policy fragments. Updated provider documentation and boundary tests. Preserved platform state paths, including the distinct Windows realm path. Validation passed: make -B build, make test, and go test -race ./pkg/broker ./cmd/epithet. Changes remain in the working copy for review.

---
# Log: 2026-10-14T11:32:12Z Brian McCallister

Replaced unpaginated user-fact enumeration with SCIM user listing through the agent and control. Removed UserLister, ListUserFacts, the directory-users operation/capability, and snapshot response types from production code. The CLI requests pages of 100, emits each before fetching the next, displays SCIM ID and externalId separately, and emits complete SCIM resources as JSON lines. Lookup-only directories cannot enumerate users. Added pagination/response-bound, refresh-on-401, incremental-output, and end-to-end source/authorization coverage. make -B build, make test, and broker/CLI race tests passed; focused client/provider/caller tests passed after final validation and visibility cleanup. The user-owned in-memory example was not edited.

---
# Log: 2026-10-17T14:59:07Z Brian McCallister

Removed derived UserNameKey from ManagedUser and all callers. Renamed Prepare to non-mutating Validate for users and groups; SCIM validates before storage. SQLite now computes its existing private username index key from UserName. Removed the arbitrary supplied-key contract test and changed SCIM checks to verify observable username uniqueness and spelling. Updated directory documentation and task design. make -B build passed; make test passed outside examples/facts/inmemory, whose existing contract failures remain. Directory race tests passed. The user-owned in-memory implementation was not changed.

---
# Log: 2026-10-17T15:17:56Z Brian McCallister

Removed blanket transaction, concurrency, snapshot and immediate-visibility guarantees from directory contracts and documentation. Version enforcement is backend-specific. Moved existing rollback, conditional-write and concurrency checks from shared storetest into SQLite-specific tests; SQLite runtime behavior and the user-owned in-memory implementation are unchanged. Shared sequential fixtures document their read-visibility assumption without making it a production backend requirement. Build and SQLite race tests passed; make test passed outside the existing in-memory failures (now four subtests). Incremental group membership operations are the next interface work discussed with the user.


### Group snapshot removal (2026-10-17)

Removed GroupSnapshot, GroupSummary and Store.Groups, including the bespoke
directory-groups control action. The CLI now lists groups through the same
agent-authenticated, paginated SCIM path as users. Group tables show ID and name;
JSON emits complete resources per line. Listing uses ListGroups with complete
memberships and makes no whole-directory snapshot or revision promise.

Build and broker/CLI race checks passed. The full suite retains the four existing
in-memory store contract failures; affected production packages pass.

### Caller-supplied audit events and removal of global revisions (2026-10-17)

All six directory mutation methods now accept an audit event. Epithet supplies
actor, action, resource ID and timestamp before calling storage; storage preserves
the event and assigns its sequence. SQLite persists it within the mutation's
transaction. The in-memory example now records and pages supplied events.

Removed directory.Revision, the LookupUser revision result, AuditEvent.Revision,
and the unused authorization-revision plumbing through control. Static directory
hashing is gone. SQLite's numeric resource-version counter and existing schema
remain internal. Optional revision metadata from external fact providers is
unchanged. The user has questioned mandatory per-resource versions too; that
contract remains unchanged pending further discussion.

Validation: make -B build and make test passed, including the in-memory contract.
Shared audit checks verify supplied event preservation for all six mutations;
SCIM checks verify event identity, actor, action and operation timestamps.

### Optional resource versions (2026-10-17)

Made directory resource versions optional through Store.SupportsVersioning.
SQLite returns true and retains its conditional-write behavior. The in-memory
example retains its resource-version counter and returns true.
Unversioned stores return empty Metadata.Version and receive empty expectedVersion.
SCIM omits ETag and meta.version for those resources. Epithet now serves accurate
etag.supported discovery because the pinned SCIM library hardcodes it to false.

The shared contract checks versions according to the declared capability. Added
HTTP coverage using fixed unversioned user and group records for discovery and
responses; specific unmatched If-Match conditions still return 412.
SQLite's versioned responses and stale-write checks continue passing.
Validation: make -B build and make test passed.

### Audit timestamps and opaque continuation (2026-10-17)

Removed sequences from directory and inventory audit events and wire models.
Audit now accepts a backend-owned opaque cursor and returns events plus next.
Callers forward cursors unchanged. Empty input starts a read; empty next ends it.
Ordering, consistency during writes, and cursor lifetime are backend properties.
SQLite uses private row positions; the in-memory directory uses slice positions.
Shared contract tests make no audit ordering assertion. Directory schema 4 removes
audit revision/sequence columns; inventory schema 2 removes its audit sequence.
Resource-version mechanisms are unchanged. Both HTTP/CLI audit pages expose events
and next, with --cursor for continuation. Validation: make -B build and affected backend contract tests pass. The full
make test run passes all other packages but fails in the unfinished in-memory
inventory implementation at memInv.Enroll (panic("implement me")). Cursor transport
coverage verifies that nonnumeric tokens are forwarded unchanged.
