---
yatl_version: 1
title: Design inventory management interface and provider discovery
id: s9cqey45
created: 2026-10-11T16:56:56.536024Z
updated: 2026-10-14T08:55:55.681712Z
author: Brian McCallister
priority: high
tags:
- design
- control
- facts
- inventory
---

# Inventory management interface and provider discovery

Implemented after explicit user authorization on 2026-10-14. Directory management
and the deferred manual-user CLI remain separately tracked in `ywxp1g89`.

## Implementation result (2026-10-14)

- Added REST inventory provider resources and signed OPTIONS/Link-Template
  discovery at the complete configured fact endpoint. Initial OPTIONS 4xx or
  success without management relations selects lookup-only use; malformed/partial
  advertisements, redirects, transport and 5xx failures remain errors.
- Control translates existing CLI commands to provider REST. Whole PUT supports
  either proposal editing or pending-to-active/denied review, not both. Strong
  ETag/If-Match protects PUT/DELETE; If-Match is covered by service signatures.
- Record/audit lists retain bounded ID/sequence continuation. List documents omit
  revisions; CLI selection reads the item to obtain its ETag before review.
- Added optional control inventory-token/inventory-token-file authentication and
  inventory CLI control-url/admin-token-file automation access. Human CLI use
  remains OIDC through the agent. Removed token retrieval and token-list CLI.
- Shared HTTP protocol and pure inventory rules serve a complete-operation Store
  contract. SQLite implements Replace/Remove atomically. Store lifetime belongs to
  its executable. No schema migration or cloud SDK dependency was introduced.
- Added a reusable store conformance suite, protocol/discovery/authentication tests,
  and ADR 0002. Firebase and DynamoDB adapters are later implementations of this
  starting boundary, not part of this change.
- Validated with make -B build, make test, and race tests for inventory and broker.
  One integration run hit a wall-clock jump and expired test credential; reruns
  passed. A remaining root-URL broker fixture was corrected for complete inventory
  fact endpoint semantics.

The decisions below preserve the design discussion; earlier statements withholding
implementation authorization and open wire details are superseded by this result.


## Agreed direction and next step

- Define only endpoints and methods required by our CLI's concrete workflows.
  The CLI is the only client driving requirements. Do not add operations for
  resource symmetry, hypothetical third-party clients, or possible future use.
  Alternate providers implement this contract; they do not justify enlarging it.
- Prefer PUT for whole-record replacement rather than PATCH. Revoke enrollment
  tokens with DELETE. Provide no token retrieval endpoints, either individual
  GET or collection listing. POST returns the newly created token; DELETE revokes
  a known token. Remove the existing inventory token list CLI command when this
  design is implemented. Atomic edit-and-approve semantics for record PUT remain
  undecided.
- Use a resource-oriented REST API over HTTP for inventory management. Do not
  introduce gRPC or retain the action-dispatch RPC envelope as the new provider
  contract. Discover resource locations through `Link-Template` headers on
  `OPTIONS` responses as recorded below. Remaining representation and HTTP
  semantics must be settled and recorded in ADR 0002.
- Use RFC 9652 Link-Template with RFC 6570 URI templates to advertise management
  resource locations and their variable slots. This resolves the member-addressing
  question without token reads or client-owned provider path construction.
  Token revocation can supply the known token through a template query variable.
- Retain existing record revision preconditions: expose the revision as a strong
  ETag and use If-Match on record PUT and DELETE. No conditional-read endpoint
  behavior is required by the CLI.
- Any 4xx response to the initial OPTIONS request at the inventory fact endpoint
  means inventory management APIs are unsupported: continue using that provider
  for data-plane lookups only. This rule is specific to discovery OPTIONS, not
  failed operations on an advertised management resource.
- The current inventory behavior/model is acceptable. Focus on exposing its
  operations through a coherent provider API, not redesigning its lifecycle.
- Add optional inventory-administration shared-secret authentication at control
  for automation alongside existing OIDC inventory-admin access. Keep this
  credential distinct from the SCIM secret and single-use enrollment tokens.
- Start at the operator interface under `epithet inventory`, not `epithet control`.
- Control fronts inventory administration and enrollment; providers own inventory
  invariants and complete mutations. CLI administration uses the agent's OIDC
  authentication and control's inventory-admin authorization.
- Keep authorization fact lookup small and independently implementable. Its
  configured URL is arbitrary; management discovery must not require a fixed
  fact lookup path or management support from data-only providers.
- Resume by mapping existing inventory operations to REST resources individually.
  The earlier A/B/C exploration remains historical rationale, not a mandate to
  redesign workflows or use command envelopes.
- Discuss and record settled contracts, alternatives and rationale in ADR 0002.
  Keep implementation planning and sequencing in this task. No ADR is written yet.

ADR 0001 is implemented. Its selector/fact semantics are the baseline, not new
work for this task. Directory-specific decisions and SCIM provisioning transport
questions belong to `ywxp1g89`.

## Agreed OPTIONS discovery shape

Send OPTIONS to the configured inventory fact URL. Advertise three URI templates
for records, enrollment tokens and audit. The accepted example is:

```http
HTTP/1.1 204 No Content
Allow: GET, OPTIONS
Cache-Control: no-store
Link-Template: "/inventory/records{/id}{?after,limit,pending}"; rel="https://epithet.dev/rel/inventory-records"
Link-Template: "/inventory/tokens{?token}"; rel="https://epithet.dev/rel/inventory-tokens"
Link-Template: "/inventory/audit{?after,limit}"; rel="https://epithet.dev/rel/inventory-audit"
```

Paths are illustrative and provider-owned; the client selects the relation and
supplies the operation's variables. Expand according to RFC 6570, then resolve
relative references against the discovery URL. Do not hard-code provider paths.

| Operation | Template | Variables |
|---|---|---|
| List records | inventory-records | Optional after, limit, pending |
| Enroll / add pattern | inventory-records | None; proposal in POST body |
| Read / replace / remove record | inventory-records | id |
| Create token | inventory-tokens | None; lifetime in POST body |
| Revoke token | inventory-tokens | token |
| Read audit | inventory-audit | Optional after, limit |

Omitted variables contribute nothing: `{/id}` disappears for collection requests,
and `{?token}` disappears for token creation. Token revocation expands to a DELETE
target such as `/inventory/tokens?token=abc123`. A caller with a known token or
record ID can address it without retrieving tokens or retaining a creation URL.

OPTIONS is defined only at the known fact endpoint for this discovery purpose.
Do not add OPTIONS discovery on the advertised resource URLs: the CLI already
knows each relation's methods and representations from the API contract. `Allow`
above describes the fact endpoint receiving OPTIONS, not the linked resources.

Any 4xx from this initial OPTIONS means no inventory-management support; continue
data-plane lookups. This fallback does not apply to management-operation errors.

References: [Link-Template, RFC 9652](https://www.rfc-editor.org/rfc/rfc9652.html)
and [URI Templates, RFC 6570](https://www.rfc-editor.org/rfc/rfc6570.html).

## Agreed record representation for GET and PUT

GET and PUT use the same record document, without an action or response envelope.
GET returns HTTP 200, Content-Type application/json and a strong ETag derived
from the existing record revision, for example `ETag: "7"`:

```json
{
  "id": "record-123",
  "status": "pending",
  "host": {
    "name": ["web.example.com", "web.internal"],
    "attributes": {
      "environment": "production"
    },
    "accounts": ["deploy"],
    "principal": {
      "mode": "epithet-principal-v1",
      "realm": "production-web"
    }
  },
  "createdAt": "2026-10-14T09:00:00Z",
  "updatedAt": "2026-10-14T09:15:00Z"
}
```

To approve this record, PUT the entire document to the expanded record URL with
`If-Match: "7"`, changing only `status` to `active`. Success returns HTTP 200,
the committed record with its updated timestamp, and the new ETag. A stale
precondition returns 412. Record DELETE also requires If-Match.

Field contracts:

- `host` and `status` are writable, subject to existing lifecycle constraints.
  Editing replaces the host specification; approval or denial changes status.
  Combined specification editing and approval remains undecided.
- `id`, `createdAt` and `updatedAt` are server-owned. Clients echo these unchanged
  in PUT. Reject attempts to alter them; the server updates `updatedAt` on commit.
- The record revision is represented by the ETag, not duplicated in the JSON.
- Use fact-API vocabulary: `name`, `attributes` and nested `principal` replace
  management's `names`, `labels` and `principal-mode`. This naming change does
  not expand the attribute types supported by the built-in store.
- Pattern records use `pattern` instead of `name` in the host specification.
- `accounts` must be explicit in a non-null host specification: null is
  unrestricted, [] permits none, and a populated array restricts account names.
  Omitting it is invalid.
- Empty token reservations use `host: null`. They can be denied or removed, but
  need a complete specification before approval.

The example ID and timestamps are illustrative. These are agreed design contracts;
no application implementation has been authorized by accepting this representation.

## Agreed record POST representation

POST to the records template with `id` omitted. The body contains `host` and,
for token-backed enrollment, `token`. Do not include `status`, record ID,
timestamps or revision. Status is derived from the operation's authorization
and enrollment credential, not chosen by the caller.

Enrollment without a token:

```json
{
  "host": {
    "name": ["web.example.com", "web.internal"],
    "attributes": {},
    "accounts": ["deploy"],
    "principal": {
      "mode": "epithet-principal-v1",
      "realm": "production-web"
    }
  }
}
```

Token-backed enrollment uses the same body with a top-level
`"token": "enrollment-token-value"`. This is the single-use enrollment credential,
not the inventory-administration shared secret. The provider atomically fills
and activates its existing reservation and consumes the token. The credential
is not part of the returned record.

An authorized administrator adding a pattern sends:

```json
{
  "host": {
    "pattern": "*.example.com",
    "attributes": {
      "environment": "production"
    },
    "accounts": ["deploy"],
    "principal": {
      "mode": "epithet-principal-v1",
      "realm": "production-web"
    }
  }
}
```

| Existing operation | Derived status | Success response |
|---|---|---|
| Enrollment without a token | pending | 201 Created |
| Enrollment with a valid token | active | 200 OK; existing reservation activated |
| Administrator adds a pattern | active | 201 Created |

Pattern admission requires inventory-admin authority through control. Direct
administrator creation of active exact-host records is not added. Preserve
existing support for pattern enrollment proposals; a pattern alone does not
confer administrator authority or bypass review.

Each success returns the complete record, its ETag and its Location. POST does
not require If-Match; token redemption checks and consumes the reservation
atomically. Human OIDC and automation shared-secret credentials are authentication
inputs, separate from the JSON enrollment token. `status` remains in record GET
responses and PUT replacements for review transitions.

## CLI-driven REST surface audit

Audited the proposed surface against `cmd/epithet/inventory.go`,
`inventory_token.go`, `admin_client.go`, and `host_enroll_registration.go`.
This is the revised proposal, not an implementation authorization. It supersedes
the endpoint suggestions and RPC alternatives in the historical exploration.

The surface needs eight management method/resource combinations plus initial
OPTIONS discovery. Resource names below denote discovered locations, not fixed
provider paths.

| Resource | Method | Concrete CLI consumer |
|---|---|---|
| Inventory fact endpoint | OPTIONS | Discover whether management/enrollment is available and locate its resources |
| Record collection | GET | inventory list, including pending filtering; resolve unambiguous names, patterns and ID prefixes |
| Record collection | POST | host enroll, with or without an enrollment token; inventory add-pattern |
| Individual record | GET | inventory show and exact-ID lookup; read before edit/review/remove; reread after a stale review |
| Individual record | PUT | inventory edit and the approve/deny choices in inventory approve |
| Individual record | DELETE | inventory remove |
| Token collection | POST | inventory token create, returning the new credential and expiry |
| Individual token | DELETE | inventory token revoke with a known token |
| Audit collection | GET | inventory audit |

Keep only the query capabilities the CLI needs: record pagination, page limit,
pending-only filtering, and audit continuation/page limit. Name/pattern/prefix
resolution currently walks record pages; it does not require a new server search
endpoint. Record GET has a real caller and avoids enumeration for a full ID.

Remove from the proposal:

- Both token GET operations, including listing, and the token list CLI command.
- Per-resource OPTIONS requests for dynamic method discovery: our CLI already
  knows the methods defined by the contract. Retain initial OPTIONS/Link-Template discovery.
- PATCH, separate approve/deny/revoke action endpoints, and separate durable
  enrollment-request or review resources.
- Individual audit-event retrieval and audit mutations; no CLI consumer exists.
- Generic search/filter/sort, arbitrary status assignment, bulk operations and
  new inventory lifecycle behavior merely to fill out REST resources.

## Accepted starting implementation boundary

Target three separately published inventory fact services: the bundled SQLite
service, a separate Firebase-backed service, and a separate DynamoDB-backed
service. Use one reusable Go inventory service package and a backend interface.
This is the accepted starting design; refine the interface based on implementing
the real backends rather than treating the sketch below as a frozen abstraction.
Acceptance does not authorize application implementation before the remaining
design discussion and ADR 0002.

Evolve the existing `factserver.InventoryHandler` and `inventory.Store` boundary.
Extract shared inventory rules currently embedded in the SQLite implementation.

| Shared implementation | Backend-specific implementation |
|---|---|
| Fact lookup and REST HTTP handlers | Database connections and schema |
| Service-key authentication and trusted actor extraction | Queries, indexes and storage encoding |
| OPTIONS and Link-Template discovery | Pagination cursors |
| JSON validation and representation mapping | Transactions and conditional writes |
| ETag/If-Match handling and HTTP error mapping | Atomic enforcement of record, name, realm and token constraints |
| Inventory validation, lifecycle rules and audit-event construction | Persistence of records, credentials and audit together |

Public OIDC/shared-secret authentication and administrator authorization remain
in control. Each service executable opens its backend, passes it and trusted keys
to the common handler, serves HTTP, and owns backend/server shutdown. The shared
package has no Firebase or AWS SDK dependency; separate adapters supply those.

The illustrative backend interface consists of complete domain operations:

```go
type Store interface {
    LookupHost(ctx context.Context, name string) (*ResolvedHost, string, error)

    Get(ctx context.Context, id string) (*Record, error)
    List(ctx context.Context, query RecordQuery) (RecordPage, error)

    Enroll(ctx context.Context, host Proposal, token string) (*Record, error)
    AddPattern(ctx context.Context, actor string, host Proposal) (*Record, error)
    Replace(ctx context.Context, actor string, record Record, version uint64) (*Record, error)
    Remove(ctx context.Context, actor, id string, version uint64) error

    CreateToken(ctx context.Context, actor string, lifetime time.Duration) (Token, error)
    RevokeToken(ctx context.Context, actor, token string) error

    Audit(ctx context.Context, query AuditQuery) (AuditPage, error)
}
```

Types and signatures are schematic. Each method serves an existing workflow.
Do not add token retrieval, generic queries, or provider-owned HTTP handlers.
Backend lifetime belongs to its executable rather than the handler's interface.

Each mutation owns its complete atomic operation. The handler must not read,
check a revision and write through separate backend calls. Shared inventory
logic validates current/proposed state and constructs the resulting state and
audit event; the backend uses it inside its transaction or conditional-write
sequence. Name/realm rules have shared meaning; the backend owns the database
mechanism ensuring those rules cannot be invalidated by concurrent changes.

A generic transaction interface beneath a shared engine was considered but is
not the starting approach: it risks becoming a database portability framework.
Firestore transaction callbacks/read ordering and DynamoDB transactional
batches/condition checks differ. Complete domain operations hide those mechanics
without requiring each provider to recreate protocol and business-rule logic.
The exact Firebase storage product remains to be selected; Firestore was the
transaction-model example used in the comparison.

Use a shared backend contract test suite for lifecycle, concurrent approval,
single-use token redemption and lookup invariants across the three backends.

## Necessary contract details still to settle

- PUT must cover current edit, approve and deny behavior with the reviewed
  version as a precondition. The current approval UI saves edits immediately and
  approves in a separate request. Atomic edit-and-approve is not needed by that
  UI and must not be introduced implicitly. The rule for a PUT that changes both
  specification and status remains a design decision. Denial must still support
  an empty pending token reservation; do not require an approvable specification
  merely because PUT carries the whole record.
- Record edits/reviews/removals already require a version check. ETag/If-Match
  is the agreed HTTP representation. Define how to bind If-Match in the signed
  request; current service signatures do not cover it. Token revocation currently
  needs no read or version precondition; do not add one that requires token GET.
- Pagination is required, including multi-page name resolution. Continuation
  encoding and links are still wire-design choices, not reasons to add endpoints
  or snapshot semantics. Preserve only the needed record and audit continuations.
- Creation and record replacement must return the record because callers display
  it and approval updates its reviewed version. Host enrollment consumes record
  ID/status; token creation consumes the credential/expiry. Token revocation and
  record removal need no response object. Keep these direct results, without a
  cross-domain union envelope.

Initial OPTIONS returning any 4xx continues to mean data-plane-only support.
Do not reuse that fallback for failed requests to advertised management resources.
The proposed no-links-on-success and 5xx/transport-error handling still need to be
settled as part of the discovery contract.

## Retained inventory exploration

The material below records the original exploration against its cited checkout.
It is not an approved specification. References to then-current behavior and
recommendations must be rechecked, especially shared directory/authentication
assumptions changed by ADR 0001. Historical logs are retained for traceability.
The RPC envelope and command-URL recommendations below are superseded by the
REST and OPTIONS/Link discovery decision above. Resource contracts must be
designed before implementation.

## Scope and ownership

There are two HTTP boundaries: callers to public control, and public control to a fact provider. The second is the provider contract under discussion. Sharing operation definitions across the boundaries is useful; their authentication remains different.

| Component | Responsibility |
|---|---|
| Public control | Authenticate administrators, check inventory-admin or directory-admin grants, authenticate external provisioning, rate-limit public enrollment, and attach trusted actor context to provider requests |
| Fact provider | Validate operations, enforce lifecycle and uniqueness rules, compare mutation preconditions, and commit facts, credentials, and audit together |
| CA | Authenticate certificate applicants and read facts; management discovery is unnecessary for issuance |
| CLI | Present records and collect decisions; it does not orchestrate a provider's transaction steps |

Providers trust the configured control signing key for private operations. A reader key cannot acquire management authority through a Link header. Human actor identity remains in the signed service request; the public caller cannot supply trusted actor or authorization-snapshot metadata.

The proposals concern the existing feature set. They do not add suspension, reactivation, bulk transactions, host polling, new roles, a generic user-management API, or automatic retry of mutations.

## What the existing implementation actually promises

The current public action catalogue contains **12 inventory operations and 3 directory administration operations**. There is also a private actor lookup and a separate SCIM tunnel. The large request structure makes this look like one API operation with many optional fields, but the backend must already understand all those distinct actions.

Several less obvious behaviors affect the design:

1. A token creates an empty pending inventory reservation. Its ID is both the token secret and the eventual record ID. Redemption fills and activates that same record. An administrator can instead fill and approve the reservation, invalidating the unused token.
2. Pending and denied records do not reserve names or affect fact lookup. Conflicts are checked when admitting a record or editing an active record. A denied record does not block a matching pattern.
3. The record model represents exact names or a pattern. Enrollment currently accepts either through the shared proposal validator; a proposed API must not silently restrict enrollment to exact hosts. The CLI usually submits exact names.
4. Editing replaces the complete specification of a pending or active record. Denied records cannot be edited or approved. Approval and denial require a pending record and the exact reviewed revision.
5. Removing a record deletes its token and its audit history. There is currently no surviving removal event. This is observable behavior, not merely a SQL implementation detail.
6. Active exact names and identical active patterns are unique. Different patterns may overlap; an ambiguous lookup fails unless an exact record resolves it. Admission does not prove arbitrary patterns disjoint.
7. Generated realms belong to one active record. Active members of a named realm must agree on labels and account sets. Pending records may temporarily disagree while being reviewed.
8. Group rebinding checks both the binding snapshot the administrator reviewed and the directory snapshot used to authorize that administrator. An ordinary fact revision is documented as logging metadata and cannot simply be substituted for this precondition.
9. Inventory mutations do not atomically check a remote directory's revision. The current stronger authorization-snapshot check applies to the directory mutation within that directory backend. No proposal here promises a transaction across services.
10. A transaction being atomic does not make a lost HTTP response safe to retry. Current requests have no durable operation-result deduplication contract.
11. A preapproval token currently accepts the bearer's valid submitted specification; it is not constrained by an administrator editing the reserved record beforehand. Redemption replaces that specification. Scoped preapprovals would be an additional behavior choice.
12. Current bounds include a one-hour default token lifetime, a maximum of 24 hours, 100-item default inventory/audit pages with a 1,000-item maximum, and a 1,000-record pending queue limit for enrollment without a token. The proposed wire schema must state agreed bounds rather than accidentally inheriting them from a CLI.

These observations were traced through the implementation and existing tests. They describe current behavior to reassess, not mandatory requirements for the new design or a claim that tests were rerun for this exploration.

## Proposal A Explicit domain commands

Keep the existing record lifecycle. Make each operation a small, independently described request with one result type. Use qualified operation names so routing and authorization do not depend on an informal string-prefix convention.

A record is an inventory authorization entry. It can describe exact names or a pattern. It may be pending, active, or denied. An empty specification is valid for a pending token reservation and can remain on that reservation after denial. Every active record has a complete valid specification. Calling this a record avoids suggesting that a pattern or empty reservation is a physical host.

### Exact inventory operations

Names below are proposed API names, not implemented commands. Trusted actor context is supplied by control separately from these inputs.

| Operation | Caller-supplied input | Result and effect |
|---|---|---|
| `inventory.enroll` | `spec`, optional `token` | Return a pending record without a token; with a valid token, atomically fill and activate its reserved record and consume the token |
| `inventory.create-pattern` | Pattern `spec` | Return a newly admitted active pattern record after all admission checks |
| `inventory.get-record` | `id` | Return the current record, or not found |
| `inventory.list-records` | `cursor`, `limit`, `pending_only` | Return a page of records; pending filtering happens before the page limit |
| `inventory.replace-record` | `id`, `expected_revision`, complete `spec` | Replace the specification of a pending or active record without changing admission status; return the committed record |
| `inventory.approve-record` | `id`, `expected_revision` | Admit the stored pending specification, revoke unused preapproval, and return the active record |
| `inventory.deny-record` | `id`, `expected_revision` | Mark a pending record denied, revoke unused preapproval, and return the record |
| `inventory.remove-record` | `id`, `expected_revision` | Remove the record under the agreed deletion policy; return an empty success result |
| `inventory.create-token` | `expires_in_seconds` | Create a single-use token and pending reservation; return the token, expiry, and reservation identity |
| `inventory.list-tokens` | `cursor`, `limit` | Return a page of preapproval states, including used, revoked, and expired tokens |
| `inventory.revoke-token` | Reservation `id` | Invalidate preapproval; keep the reserved record and return an empty success result |
| `inventory.read-audit` | `cursor`, `limit` | Return a page of surviving inventory events and a continuation cursor |

All operations except enrollment require an authorized inventory administrator on the public boundary. The provider sees control's signature and the signed administrator identity. Enrollment uses the existing nonhuman flow and validates any supplied preapproval token atomically in the provider.

`replace-record` deliberately has no status field. `approve-record` approves the exact stored revision. `deny-record` is a review outcome, not an access-deny rule. `remove-record` removes inventory state; deleting an exact record can reveal an existing matching pattern. It also does not revoke certificates already issued.

The operation set has four reads and eight mutations. Most of the specification fits into four groups: enrollment/admission, record inspection/editing, preapproval, and audit. All twelve represent existing behavior.

### Why A is viable

A provider can implement one validator and one transaction per mutation. Existing CLI workflows map directly to the operations. It requires no new durable object types, draft lifecycle, or migration of pending records into another collection. The client can use typed methods without exposing a giant request containing irrelevant fields.

The cost is twelve named inventory operations and retention of the reservation/token coupling. Review followed by approval remains two operations when an administrator edits first. The revision check makes that sequence safe, but a saved edit can remain pending if approval never happens.

## Proposal B Workflow review and explicit token redemption

Keep the same record model, but make two workflow choices visible in the operations.

Replace A's `inventory.enroll` with:

| Operation | Input | Result |
|---|---|---|
| `inventory.request-enrollment` | `spec` | Create and return a pending record |
| `inventory.redeem-token` | `token`, `spec` | Atomically fill and activate the token's reservation |

Replace A's separate approval and denial operations with:

| Operation | Input | Result |
|---|---|---|
| `inventory.review-record` | `id`, `expected_revision`, a review decision | Return the committed active or denied record |

The decision has exactly two variants: `{"approve":{"spec":...}}` or `{"deny":{}}`. Approval always supplies the complete specification being approved; denial cannot carry a specification. Both variants require a pending record. The backend checks its current revision and commits the replacement and decision together. This is a proposed behavior change from the current edit-then-approve sequence.

All nine other A operations remain: create-pattern, get-record, list-records, replace-record, remove-record, create-token, list-tokens, revoke-token, and read-audit. **B therefore also has twelve inventory operations.** Its value is a different transaction boundary, not a lower operation count.

An administrator may still save a draft using replace-record. That preserves the current ability to edit now and decide later. Approval can instead send the final reviewed specification in one operation without first exposing an intermediate saved draft.

### Why B is viable

The two enrollment paths have fixed result states and distinct request schemas. Atomic review matches the common human task of adjusting a proposal and accepting it. Providers still own all admission checks and the transaction remains local.

B needs a precise two-variant decision schema, new audit semantics for edit-and-approve, and updated CLI behavior. Approval carries a full specification even if the administrator changed nothing. Splitting public enrollment also duplicates some request routing and rate-limit classification. The existing single enroll operation is already straightforward: an optional credential determines whether a review is needed.

B is preferable if atomic edit-and-approve is a product requirement. It is not justified solely by making an API appear smaller. A can later adopt that transaction boundary as a deliberate change, without first separating enrollment requests into new durable objects.

## Proposal C Separate requests admissions and preapprovals

Model an enrollment request, an admitted inventory record, and a preapproval grant as distinct objects. Each has a narrower lifecycle. Pending and denied requests never appear as admitted records; creating a preapproval does not create an empty inventory record.

A complete operation catalogue would be:

| Domain | Operations |
|---|---|
| Enrollment requests | `submit-request(spec)`, `get-request(id)`, `list-requests(cursor,limit)`, `replace-request(id,revision,spec)`, `decide-request(id,revision,approve-spec-or-deny)`, `remove-request(id,revision)` |
| Admitted inventory | `create-pattern(spec)`, `get-record(id)`, `list-records(cursor,limit)`, `replace-record(id,revision,spec)`, `remove-record(id,revision)` |
| Preapproval | `create-preapproval(lifetime)`, `list-preapprovals(cursor,limit)`, `revoke-preapproval(id)`, `redeem-preapproval(token,spec)`, `complete-preapproval(id,revision,spec)` |
| Audit | `read-audit(cursor,limit)` |

This has **seventeen inventory operations**. The administrator-only complete-preapproval operation preserves today's ability to finish a reservation without the host redeeming its token. Omitting it would remove an existing workflow.

Approving a request creates an admitted record and closes the request atomically. Redeeming or administratively completing a preapproval creates the admitted record and consumes or withdraws its credential atomically. Responses explicitly identify both the source request/grant and resulting record. This avoids requiring their IDs to be the same.

### Why C is viable

Each object has fewer invalid states. Inventory listing is purely admitted authorization state, and enrollment review can be implemented as a distinct capability. An implementation with separate collections could make those boundaries natural.

The cost is visible across the system: more IDs, more get/list/remove operations, decisions about the retention and deletion of linked objects, and transactions spanning requests or grants and admitted records. Existing list/show/edit behavior changes. Migrating existing reservations and preserving relationships is required. The CLI needs to distinguish reviewing a request from editing a record.

C is a reasonable product redesign if independent enrollment workflows are wanted. The current request is about a small provider contract, so the added concepts outweigh the benefit at present.

## Scenario walkthroughs and second comparison

The candidates were compared against complete user tasks and concurrent outcomes, rather than operation counts alone.

| Scenario | A | B | C |
|---|---|---|---|
| Host arrives without a token | enroll returns pending record | request-enrollment returns pending record | submit-request returns enrollment request |
| Admin edits but does not approve | replace-record saves pending specification | same operation remains available | replace-request saves the request |
| Admin edits and approves | replace-record, then approve-record with the returned revision | one review-record with final specification | decide-request creates a separate admitted record |
| Two admins review the same version | one mutation succeeds; the stale mutation changes nothing | same comparison, encompassing edit and decision | request revision protects the decision and record creation |
| Two hosts redeem one token | exactly one activation succeeds | same, through redeem-token | exactly one grant consumption and record creation succeeds |
| Token redeemed while admin completes reservation | current record revision/status and credential checks decide the winner | same record-level conflict | grant must coordinate host redemption with complete-preapproval |
| Pending name conflicts with an active record | save remains allowed; approval fails without partial activation | review approval fails without saving its included specification | admission fails without creating an active record |
| Active record moves to another name or realm | replace-record atomically releases old claims and acquires new claims | same | same admitted-record mutation |
| Active exact record is removed above a wildcard | existing matching pattern becomes effective | same | same; request history must not affect lookup |
| A pending or denied record names an existing host | it remains inert | same | isolation follows from the separate request model |
| Response is lost after a commit | outcome may be unknown; no automatic mutation retry guarantee | same | same, with more identities to reconcile |

B provides the best single-step human review, but its failed approval also discards the included edit. A preserves the saved pending edit when a later approval fails. Both are useful semantics; they are different behavior, not equivalent spellings.

C makes pending-state isolation structural, but A and B already enforce and test that property. The structural benefit does not remove the name, realm, credential, and concurrency rules required at admission.

## Overall comparison

These judgments weigh the existing workflows and invariants above. Operation count is a measure of surface area, not a complexity score.

| Criterion | A Explicit commands | B Atomic review workflow | C Separate request model |
|---|---|---|---|
| Inventory operation count | 12 | 12 | 17 |
| Current workflow preservation | Highest; wire cleanup can preserve the lifecycle | Requires deciding whether approval should also commit the final edit | Changes record lists, identifiers, and request/grant lifecycles |
| Individual request clarity | Highest; each mutation has one intent and narrow fields | Clear enrollment paths; review has a two-variant decision | Narrow individual objects, but more relationships to learn |
| Administrator review | Saved edit followed by approval | One atomic edit-and-approve, with separate draft saving available | Review creates an admitted record from another object |
| Backend transaction burden | Existing record, claims, credential, audit | Essentially the same as A | Adds cross-object lifecycle coordination |
| Persistence migration | None inherent in the operation design | None inherent in the operation design | Required for existing reservations and pending records |
| Best reason to choose it | Publish a small understandable contract for existing behavior | Make final review an atomic product operation | Make enrollment requests a separately managed product concept |

A wins on present scope and ease of independent implementation. B is a close alternative with a concrete user benefit, provided its changed review semantics are desired. C is viable but does not make the whole system smaller today.

### Recommended lifecycle written explicitly

| Operation | Before | After |
|---|---|---|
| enroll without token | No record | Pending with complete specification |
| create-token | No reservation | Pending reservation with empty specification and live token |
| enroll with token | Pending reservation and usable token | Same record active with submitted specification; token consumed |
| create-pattern | No record | Active pattern |
| replace-record | Pending or active | Same status, new specification and revision |
| approve-record | Pending with valid specification | Active; unused token revoked |
| deny-record | Pending, including empty reservation | Denied; unused token revoked |
| remove-record | Any existing status | Absent, with current cascading deletion semantics unless explicitly changed |
| revoke-token | Existing token and associated record | Token revoked; record status unchanged and its revision updated |

Revision-checked operations are replace, approve, deny, and remove. Token revocation currently does not require a caller-supplied record revision. A failed mutation leaves the operation's state unchanged. Denied records have no transition back to pending or active in this proposal. Exact-name and pattern specifications can be replaced under the current validation/admission rules; the API does not invent an immutable record kind.

## Wire shape and implementation burden

For A or B, prefer one complete management URL per provider with an explicit operation name and typed parameters. Each operation has a direct result body. A transport envelope can be small without turning into a bag of every possible input:

```json
{
  "operation": "inventory.approve-record",
  "parameters": {"id": "record-id", "expected_revision": "revision-value"}
}
```

The successful response is the committed record. A removal can return `{}`. List operations return a page. Errors have one stable code and a human-readable message. Unknown operations and irrelevant fields are rejected; they cannot silently select a different action or broaden access.

On the public boundary, the service authenticates and classifies the operation. On the private boundary it adds trusted authorization metadata and signs the request. Both boundaries can use the same domain parameter/result definitions. There is no need to decode an action into a method only to reconstruct a second, differently shaped action.

The provider remains responsible for operation-specific validation. Control must still recognize each operation's destination and authorization class; a blindly forwarded arbitrary method is not an authorization design. A finite operation catalogue is sufficient. No generic plugin framework or new code-generation system is needed to express it.

### Common rules worth standardizing

- **Record IDs:** opaque identifiers. Their allocation is provider-owned. The existing 64-hex display/prefix-resolution assumptions would need adjustment if arbitrary provider IDs are adopted.
- **Record revisions:** opaque equality preconditions. They bind a mutation to the exact record reviewed. They are never client-incremented timestamps or counters.
- **Pages:** `{items, next_cursor}` with an opaque cursor and a bounded limit. The provider owns ordering; cursors are scoped to the operation and filters. A page is coherent, but pages are not promised to share a historical snapshot. This is a proposed replacement for exposing record IDs and numeric audit offsets as cursors.
- **Replacement:** the complete editable specification, with explicit account restrictions. Preserve the distinction between omitted accounts, unrestricted `null`, and empty `[]`.
- **Failures:** distinguish invalid input, unauthenticated/forbidden, missing resource, stale review, admission conflict, invalid token, unsupported operation, and unavailable provider. Authentication and internal failures stay distinct from a missing record.

The numeric HTTP status mapping can follow after these meanings are agreed. Separating stale-review and admission-conflict error codes is useful even if they share a status: the former requires re-reading, while the latter requires resolving the conflicting authorization state. Messages are explanations, not machine-readable discriminators.

A smaller command set should not be purchased with a generic patch language, arbitrary status assignment, or client-visible begin/commit calls. Those mechanisms make a simple-looking interface harder to implement correctly.

## Alternate backend assessment

For the Firebase example, this assessment uses **Cloud Firestore** as an illustrative storage engine. It is a feasibility sketch, not an implementation or a claim about every Firebase database product.

Firestore supports atomic multi-document transactions, and may rerun the transaction callback after concurrent changes. Reads must precede writes. Thus a provider can own the complete admission transaction while its HTTP client sends a single domain operation. External side effects must not occur inside a retryable transaction callback. [Firestore transactions](https://firebase.google.com/docs/firestore/manage-data/transactions)

A plausible internal design would use documents for the inventory record, credential state, exact-name claims, and realm membership constraints. A transaction reads their current versions, validates all relevant constraints, then commits record/claim/credential/audit changes together. This is an inference about implementation structure, not an obligation in the wire contract. The protocol should require the outcome and isolation properties, not these document layouts.

A and B need substantially the same transaction scope. B adds no new storage primitive for atomic review. C adds request/grant lifecycle and cross-object bookkeeping; Firestore does not make that application complexity disappear.

Opaque revisions and pagination cursors let a provider use its native versioning and continuation mechanism. However, changing a revision's encoding does not remove real global semantics: a coherent directory authorization snapshot still needs a validity check, and an ordered audit feed still needs an ordering guarantee. Firestore documents identify single-document contention and sequential indexing as scaling considerations; cursors are preferable to offsets. A shared counter is possible, but should not become a requirement merely because the SQLite implementation has one. [Firestore design guidance](https://firebase.google.com/docs/firestore/best-practices)

The hardest provider requirements are invariant enforcement, coherent authorization snapshots, ordered audit continuation, and the current atomic deletion of potentially many audit events. These are more consequential than whether the command is named approve or review. No claim of a production-ready Firestore backend follows from its transaction support alone.

## Contract decisions exposed by the exploration

These are specific decisions to make before freezing a provider version. They are not implementation work authorized by this exploration.

| Decision | Current behavior | Recommendation for discussion |
|---|---|---|
| Token, secret, and record identity | One value serves all three; listing can expose the token value | Name credential and record identity separately in the schema. Preserve the reservation workflow. Changing secret disclosure or allocation is a separate behavior decision |
| Record removal and audit | Removes record, credential, and all its audit events atomically | Decide deliberately whether this is the portable contract. Retaining events or purging later changes semantics and must be explicit |
| Review transaction | Save an edit, then approve the stored revision | Choose A unless atomic edit-and-approve is explicitly wanted; B is fully specified if it is |
| Pattern scope of enrollment | Shared validation allows a pattern proposal | Preserve it in an API cleanup or explicitly decide to restrict it; the operation name must not conceal a restriction |
| Pagination and versions | Record IDs/numeric sequences and numeric edit revisions leak into callers | Prefer opaque wire values and returned cursors; account for corresponding CLI changes before implementation |
| Repeated or uncertain mutations | No durable HTTP deduplication; some repeated operations change revisions/audit | Preserve no-automatic-retry behavior initially. Do not promise exactly-once execution or use JWT jti as an idempotency key |

For token revoke, current behavior invalidates the token but retains the record and increments its revision, even when repeated. Expiry and revocation prevent redemption; they do not by themselves remove or deny the pending record. An API description should say that directly.

## Discovery consequences after the operation set is chosen

Signed OPTIONS at the configured fact URL is the favored bootstrap. It requires no fabricated hostname or user ID and can advertise management even when there are no records. CA can continue using GET alone for facts.

Advertise complete URLs for coherent APIs: directory management, inventory management, and optional provisioning. A domain command uses the advertised management URL without appending operation paths. This revises the earlier idea of reproducing the current `/manage`, `/actor`, and `/scim` routes one-for-one in Link relations.

Directory management and SCIM discovery are tracked in `ywxp1g89`. Settle the inventory capability representation here without importing the superseded directory-binding catalogue.

An absent capability and a failed discovery request remain different outcomes. A listed capability that later fails is an error, not permission to silently fall back to another mode. The exact handling of a data-only provider with no OPTIONS implementation remains a bootstrap decision.

Unix socket addressing also remains separate: a socket path identifies the connection, while the fact endpoint and relative management links identify HTTP targets. Links can preserve a socket connection for relative targets, but cannot supply the initial missing fact path. The address format still needs a decision.

## Discussion order

1. Start with the operator's inventory CLI workflows and agree required behavior.
2. Reassess A/B/C against those requirements; no alternative is selected yet.
3. Settle token identity, review transactions, deletion/audit semantics and opaque
   revisions/cursors before claiming a portable provider contract.
4. Specify the inventory operations, discovery and transport contracts.
5. Record the settled design and rationale in ADR 0002 before implementation.

## Evidence in the current checkout

The baseline was the source tree at parent change `qqkmuxpr`, commit `a8a41523` (the empty working change initially had no source modifications).

- `pkg/facts/admin_api.go:19`: current request/response union, records, credentials, and directory snapshots.
- `pkg/facts/inventory/store.go`: complete inventory storage contract and its documented invariants.
- `pkg/facts/inventory/sqlitestore/store.go:477`: pending enrollment and atomic token redemption.
- `pkg/facts/inventory/sqlitestore/store.go:540`: revision checks and edit/approve/deny/remove transitions.
- `pkg/facts/inventory/sqlitestore/store.go:654`: token creation and pending reservation.
- `pkg/facts/inventory/sqlitestore/store.go:327`: mutation/audit commit and deletion semantics.
- `pkg/facts/inventory/sqlitestore/reservation_test.go`: reservation completion, withdrawal, and identity preservation.
- `pkg/facts/inventory/sqlitestore/managed_test.go`: concurrent admission/redemption, realm constraints, and pending/denied inertness.
- `pkg/facts/inventory/sqlitestore/managed_pattern_test.go`: pattern enrollment, ambiguity, exact-name precedence, and lifecycle.
- `pkg/facts/inventory/sqlitestore/managed_sqlite_test.go:80`: atomic removal and cascading audit/token deletion.
- `pkg/facts/control/server.go:106`: public authorization and action dispatch; `:257`: managed versus read-only actor lookup.
- `pkg/facts/server/backend.go:29`: private actor/SCIM/management routes and service authorization.
- `pkg/facts/auth.go`: signed actor, request method/target/body binding, and no header-precondition binding.

No application code was changed, no normative API was frozen, and no backend implementation was started. This task retains the exploration and the decisions required before implementation.

---
# Log: 2026-10-11T16:56:56Z Brian McCallister

Created task.

---
# Log: 2026-10-11T17:05:14Z Brian McCallister

Completed design exploration: compared three exact operation sets, checked lifecycle and concurrency scenarios against current code and tests, assessed Firestore portability, and documented remaining contract decisions. Recommendation is explicit domain commands; application implementation remains unapproved.

---
# Log: 2026-10-12T09:04:43Z Brian McCallister

Deferred control-plane API design until Writ structured selectors, provider-defined attributes, and multi-valued names land. Recorded the revised direction and withdrew workflow preservation as a design requirement; retain the proposals for reassessment afterward.

---
# Log: 2026-10-12T09:09:40Z Brian McCallister

Recorded the agreed Writ evolution and rationale in docs/adr/0001-writ-object-selectors-and-provider-facts.md. This ADR is the design record to review before implementation planning; finalize Writ semantics and land them before resuming the control-plane API contract.

---
# Log: 2026-10-12T09:12:40Z Brian McCallister

Corrected the Writ discussion scope: principal realms are a certificate mechanism, not an aspect of policy. Removed shared-realm assessment as a Writ design question from ADR 0001 and this task.

---
# Log: 2026-10-12T09:16:42Z Brian McCallister

Writ evolution work is tracked in rv3znarg. Keep open questions, implementation planning, and sequencing in YATL; ADR 0001 records the technical decision and lasting rationale. Resume the control-plane contract after the Writ work lands.

---
# Log: 2026-10-12T09:17:51Z Brian McCallister

Added blocker: rv3znarg

---
# Log: 2026-10-12T13:16:07Z Brian McCallister

ADR 0001 implementation is complete: flat string predicates, explicit name/id, structured groups, provider-owned eligibility, and unchanged account filters. Historical group bindings and directory-bind are removed. Reassess the management proposal against these implemented semantics; discovery and broader workflows remain design-only.

---
# Log: 2026-10-13T15:14:59Z Brian McCallister

Started working.

---
# Log: 2026-10-13T15:22:15Z Brian McCallister

Agreed directory management uses SCIMv2 rather than a parallel user/group API. Control accepts the existing SCIM token as an optional shared secret and also OIDC users with directory-admin grants; omitting the secret does not disable authorized OIDC access. Minimal SCIM CLI remains proposed, with its command set open. Implementation remains design-only.

---
# Log: 2026-10-13T15:22:33Z Brian McCallister

Clarified and agreed: CLI SCIM operations use OIDC via the existing agent authentication path, with directory-admin authorization at control.

---
# Log: 2026-10-13T15:24:24Z Brian McCallister

Agreed operator commands belong under directory and inventory, not control or scim. Exact verbs remain open. Discuss remaining decisions, then record the settled design in ADR 0002; retain implementation planning in this task.

---
# Log: 2026-10-13T15:27:18Z Brian McCallister

Agreed CLI resource references accept names when unique. Resolve to SCIM IDs, reject missing or ambiguous names, and retain explicit ID addressing. ID-versus-name syntax remains open.

---
# Log: 2026-10-13T15:37:51Z Brian McCallister

Agreed built-in directory retains a single userName, projected as a one-element fact name collection. User creation takes positional NAME; optional --id supplies authentication identity via SCIM externalId and defaults to NAME. No multivalued-name persistence expansion.

---
# Log: 2026-10-13T15:43:12Z Brian McCallister

Priority clarified: inventory management is high priority. Defer manual directory user creation/editing without blocking inventory work. Resume design from inventory operator interfaces and workflows; retain directory decisions and notes for later.

---
# Log: 2026-10-13T15:44:53Z Brian McCallister

Removed blocker: rv3znarg

---
# Log: 2026-10-13T15:45:10Z Brian McCallister

Split directory management into ywxp1g89. This task now owns high-priority inventory interface, operations and discovery design; remains in progress. Retained detailed inventory alternatives and historical logs. Removed the completed ADR 0001 blocker. Directory CLI work does not block inventory.

---
# Log: 2026-10-13T15:51:30Z Brian McCallister

Agreed REST over HTTP for the inventory provider management API, with resource locations discovered through Link headers on OPTIONS responses. No gRPC; earlier action-dispatch RPC proposal is superseded. Current inventory model is acceptable. Optional inventory admin shared secret supports automation. Resource mappings and HTTP contracts remain design work for ADR 0002.

---
# Log: 2026-10-13T15:54:59Z Brian McCallister

Agreed discovery rule: any 4xx response to initial inventory OPTIONS means management APIs are unsupported; continue data-plane lookups. Preparing a REST resource proposal around records, enrollment tokens and audit; the resource/method mapping is not yet agreed.

---
# Log: 2026-10-13T15:58:28Z Brian McCallister

Explicit scope constraint: our CLI is the only client; define only endpoints it needs, never operations for symmetry or hypothetical usefulness. Remove individual token GET. Prefer whole-record PUT and token DELETE; combined edit/approve semantics remain open.

---
# Log: 2026-10-13T15:59:00Z Brian McCallister

Token scope narrowed further: no retrieval at all, including collection listing. Keep POST creation returning the new token and DELETE revocation of a known token. This supersedes the previous note retaining listing and entails removing the current token list CLI command during implementation.

---
# Log: 2026-10-13T16:00:54Z Brian McCallister

Audited REST proposal against actual CLI callers. Retain eight management method/resource combinations plus initial OPTIONS. Remove all token reads and per-resource method-discovery OPTIONS. Preserve real record reads, pagination, pending filtering and audit continuation. Flag member addressing for revoke-by-token/full-ID lookup, signed version preconditions, constrained record creation, and PUT transition semantics as necessary unresolved contract details; no new application code.

---
# Log: 2026-10-13T16:07:58Z Brian McCallister

Agreed RFC 9652 Link-Template discovery using RFC 6570 URI templates. Token revocation can use a token query variable. Also confirmed existing record revisions should be exposed as ETags with If-Match on replacement and removal. Preparing illustrative OPTIONS headers; exact relation names and pagination variable encoding remain proposed.

---
# Log: 2026-10-14T07:54:55Z Brian McCallister

Saved accepted OPTIONS response with three Link-Template relations for records, tokens and audit, including variable/method usage and illustrative provider-owned paths. OPTIONS discovery is required only on the known fact URL; no recursive OPTIONS on advertised resources. Any initial OPTIONS 4xx means data-plane-only support. Member addressing is settled by template expansion; ETag/If-Match is agreed, with signature binding still to design.

---
# Log: 2026-10-14T08:04:53Z Brian McCallister

Accepted matching GET/PUT record JSON: id, status, host and camelCase timestamps; host uses name or pattern, attributes, accounts and nested principal. Version is in ETag with If-Match. Echo server-owned fields unchanged; empty reservations use host:null. PUT returns committed record and new ETag. Combined edit-and-approve remains undecided.

---
# Log: 2026-10-14T08:10:08Z Brian McCallister

Accepted POST record bodies containing host and optional enrollment token, with no caller-supplied status. Provider derives pending for untokened enrollment and active for valid token redemption or administrator-added patterns. New records return 201; reservation activation returns 200. Responses include record, ETag and Location. No direct active exact-host creation added.

---
# Log: 2026-10-14T08:15:25Z Brian McCallister

Accepted as a starting implementation design: reusable inventory HTTP service plus complete-domain-operation Store interface for bundled SQLite and separate Firebase/DynamoDB services. Share protocol handling and inventory rules; backends own atomic storage mechanics. Refine signatures through actual backend work rather than freeze the sketch. Preserve control authorization and use shared backend contract tests.

---
# Log: 2026-10-14T08:55:55Z Brian McCallister

Implemented provider REST with Link-Template discovery, complete-operation Store and shared rules, optional inventory automation secret, token enumeration removal, CLI adaptation, ADR 0002 and reusable backend contract tests. Full build/test and inventory/broker race checks pass; cloud adapters remain separate work.

---
# Log: 2026-10-14T08:55:55Z Brian McCallister

Closed: Inventory API and reusable backend starting design implemented and validated; directory work remains ywxp1g89.
