---
yatl_version: 1
title: Design fact provider management operations and discovery
id: s9cqey45
created: 2026-10-11T16:56:56.536024Z
updated: 2026-10-12T09:17:51.205352Z
author: Brian McCallister
priority: medium
tags:
- design
- control
- facts
blocked_by:
- rv3znarg
---

# Fact provider management API exploration

Design proposal for discussion. Implementation is not authorized by this task. The working application remains unchanged.

## Deferred pending Writ semantics

Control-plane API design is deferred until the Writ selector and fact semantics refinement lands. Do not freeze the fact-service APIs against the current name-only group model or SCIM reconciliation workflows.

The earlier preference for Proposal A below was based on preserving existing workflows. That is no longer a requirement: the user explicitly permits reconsidering those workflows, particularly SCIM reconciliation. The three proposals remain useful exploration, but A is not an agreed final design.

Direction established in discussion:

- Trust the IdP's current group names, including deletion and recreation under the same name. Historical ownership of a name need not be preserved through aliases, tombstones, or manual rebinding.
- Preserve the ability to select a particular group identity when multiple groups share a name. Group membership facts should retain structured identity and attribute information.
- Use object filters such as `group{id:abc123}` and `user{employmentType:contractor, department:engineering}`; the parallel host form is `host{environment:sandbox, region:eu-west-1}`.
- Filters use colons, and comma-separated predicates are AND on the same object. A group filter must be satisfied by one membership, not by distributing predicates across different groups.
- Express OR through repeated rules, rather than inline alternatives. This revisits existing outer selector-set alternatives as well as defining the new filters; deny precedence must remain explicit.
- Permit provider-defined attributes instead of a fixed vocabulary tied to SCIM or the built-in inventory. Path notation for nested attributes remains a candidate.
- The short form selects the `name` attribute. The fact-service reply contains the mapped names; Writ has no provider-controlled default-attribute configuration.
- `name` is multi-valued for users, groups, and hosts. A name selector matches any supplied name. Users will commonly have one username but may have aliases; adding an alias is authorization-relevant.

Still resolve in the Writ work: precise fact shapes and group identity source/scope, typed values and collection matching beyond names, missing-attribute and negation semantics, nested paths, and hostname-pattern behavior. These are discussion points, not authorization for speculative features.

Resume control-plane design after those semantics land: identify the administrator operations still needed, reconsider directory binding/reconciliation operations, then settle operation schemas and OPTIONS/Link capability discovery. Preserve the agreed direction that the data-plane endpoint is an arbitrary configured URL with query parameters as its contract; discovery should advertise optional management support without requiring a fixed lookup path.

## Earlier proposal assessment

The initial recommendation was **Proposal A: explicit operations over the existing inventory lifecycle**, with operation-specific requests and results. Proposal B offers an atomic review workflow. Proposal C separates enrollment from admitted inventory with a larger domain model. Reassess these choices against the revised semantics rather than treating existing workflows as requirements.

The objective is a contract that an independent fact provider can understand and implement. OPTIONS and Link discovery should describe that contract after its operations are settled. They should not freeze the current route names, Go types, or SQLite representation.

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

The current public action catalogue contains **12 inventory operations and 4 directory administration operations**. There is also a private actor lookup and a separate SCIM tunnel. The large request structure makes this look like one API operation with many optional fields, but the backend must already understand all those distinct actions.

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

### Exact directory operations

| Operation | Caller-supplied input | Result and effect |
|---|---|---|
| `directory.read-actor` | Authentication subject `id` | Return the user's current authorization view and an opaque authorization revision from one coherent snapshot; missing or inactive users cannot authorize an administrator |
| `directory.list-users` | None in the initial behavior-preserving contract | Return the current user facts snapshot, including inactive users and policy-visible groups |
| `directory.read-bindings` | None | Return group identities, names, alias/conflict/deletion state, and an opaque binding revision |
| `directory.bind-group` | `group_id`, `alias`, `expected_revision` | Bind or rebind the alias after checking the reviewed binding revision and control's trusted authorization revision; return empty success |
| `directory.read-audit` | `cursor`, `limit` | Return a page of directory events and a continuation cursor |

`read-actor` is a service operation by control, before human authorization. The remaining four require directory-admin authorization. `bind-group` additionally carries the trusted authorization revision obtained by control, outside caller-supplied parameters.

Keep the distinction between authentication subject IDs and provisioned group/resource IDs explicit in field names. The ordinary fact response stays sufficient for authorizing administration against a read-only directory; a directory supporting binding mutations must also support the coherent actor snapshot they require.

User and binding listings currently return whole snapshots. Paging them is potentially worthwhile, but requires defining snapshot consistency across pages. It should not be smuggled into an operation rename, and it is not assumed in the count above.

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

All nine other A operations remain: create-pattern, get-record, list-records, replace-record, remove-record, create-token, list-tokens, revoke-token, and read-audit. Directory operations remain the same. **B therefore also has twelve inventory operations.** Its value is a different transaction boundary, not a lower operation count.

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

This has **seventeen inventory operations**, with the same five directory operations as A. The administrator-only complete-preapproval operation preserves today's ability to finish a reservation without the host redeeming its token. Omitting it would remove an existing workflow.

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
| Admin authorization changes before group rebind | bind-group rejects the old authorization snapshot | same | same; inventory model changes do not help |
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
- **Directory authorization revisions:** separately named coherent-snapshot preconditions. They must not be confused with advisory fact revisions or record edit revisions.
- **Pages:** `{items, next_cursor}` with an opaque cursor and a bounded limit. The provider owns ordering; cursors are scoped to the operation and filters. A page is coherent, but pages are not promised to share a historical snapshot. This is a proposed replacement for exposing record IDs and numeric audit offsets as cursors.
- **Replacement:** the complete editable specification, with explicit account restrictions. Preserve the distinction between omitted accounts, unrestricted `null`, and empty `[]`.
- **Failures:** distinguish invalid input, unauthenticated/forbidden, missing resource, stale review, admission conflict, invalid token, unsupported operation, and unavailable provider. Authentication and internal failures stay distinct from a missing record.

The numeric HTTP status mapping can follow after these meanings are agreed. Separating stale-review and admission-conflict error codes is useful even if they share a status: the former requires re-reading, while the latter requires resolving the conflicting authorization state. Messages are explanations, not machine-readable discriminators.

A smaller command set should not be purchased with a generic patch language, arbitrary status assignment, or client-visible begin/commit calls. Those mechanisms make a simple-looking interface harder to implement correctly.

## Directory and provisioning alternatives

### Keep actor inspection inside the management contract

A managed directory can expose read-actor as a service-only operation on its management URL; it does not require a special hard-coded `/actor` route or a human role before the user has been authorized. Keep the actual coherent snapshot semantics.

Eliminating this operation by upgrading every ordinary user lookup revision into an authorization precondition would enlarge the read-only provider contract. A directory that only supplies facts should not need a mutation-consistency protocol. Conversely, a directory implementing bind-group must provide the authorization snapshot needed by that operation. OPTIONS can describe supported operation groups; it need not create a link for every command.

There is no need to add CRUD operations for users to the human administration API. Existing human directory tasks are inspection and alias binding. Provisioning already has a distinct caller and protocol.

### Three provisioning boundaries

| Boundary | Benefit | Cost and recommendation |
|---|---|---|
| Keep the current SCIM request tunnel | Smallest immediate implementation change; preserves existing adapter | Freezes a bespoke HTTP-inside-JSON envelope and its header allowlist; acceptable temporarily, weak as the long-term public provider contract |
| Advertise an optional SCIM endpoint and forward signed HTTP | Provider owns the existing provisioning protocol; alternate directories can implement it directly | Requires a precise route/base-URL and conditional-header binding design; preferred direction for a separate provisioning contract |
| Move the SCIM adapter to control and define provider user/group operations | Providers can work with domain records without interpreting SCIM | Adds roughly ten user/group CRUD/read operations plus provisioning identity/version/alias semantics to the private API; broader provider contract and more translation in control |

Prefer an optional, separately specified SCIM capability. It is not a requirement for a provider that only supports inventory management or reads an existing directory. The current adapter supports a selected user/group projection, create/replace/get/list/delete, and explicitly rejects PATCH and unsupported query parameters. The proposal does not promise full SCIM support.

There is one concrete dependency before replacing the tunnel: the current request signature binds method, target, and body, but not arbitrary HTTP headers. Today the tunneled If-Match value is protected because it is inside the signed body. A direct SCIM hop must preserve equivalent integrity for the mutation precondition. Forwarding the header alone would lose that guarantee. This is a reason to design the provisioning hop separately, not to add all SCIM operations to basic management.

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
| Whole directory snapshots | User and binding listings are unpaged | Keep that limitation visible initially; introduce paging only with defined consistency semantics |
| Repeated or uncertain mutations | No durable HTTP deduplication; some repeated operations change revisions/audit | Preserve no-automatic-retry behavior initially. Do not promise exactly-once execution or use JWT jti as an idempotency key |

For token revoke, current behavior invalidates the token but retains the record and increments its revision, even when repeated. Expiry and revocation prevent redemption; they do not by themselves remove or deny the pending record. An API description should say that directly.

## Discovery consequences after the operation set is chosen

Signed OPTIONS at the configured fact URL is the favored bootstrap. It requires no fabricated hostname or user ID and can advertise management even when there are no records. CA can continue using GET alone for facts.

Advertise complete URLs for coherent APIs: directory management, inventory management, and optional provisioning. A domain command uses the advertised management URL without appending operation paths. read-actor can be part of the directory management operation set. This revises the earlier idea of reproducing the current `/manage`, `/actor`, and `/scim` routes one-for-one in Link relations.

Partial directory support is real: the static directory can list users but cannot rebind managed aliases. Discovery therefore needs defined capability groups or an explicit supported-operation list; a single boolean `supports control` is insufficient. For example, advertising bind-group must also guarantee read-bindings and read-actor. Choose that discovery representation after agreeing the operation catalogue, rather than inventing dozens of relation types now.

An absent capability and a failed discovery request remain different outcomes. A listed capability that later fails is an error, not permission to silently fall back to another mode. The exact handling of a data-only provider with no OPTIONS implementation remains a bootstrap decision.

Unix socket addressing also remains separate: a socket path identifies the connection, while the fact endpoint and relative management links identify HTTP targets. Links can preserve a socket connection for relative targets, but cannot supply the initial missing fact path. The address format still needs a decision.

## Recommendation and discussion order

1. Adopt A's twelve inventory and five directory operations as the baseline to review. Most simplicity comes from their specific input/result contracts and ownership, not from combining verbs.
2. Decide between separate approve/deny and B's atomic review using the concrete saved-edit behavior above. Keep the current single record lifecycle unless C's separate request model serves an actual product need.
3. Settle token identity and deletion/audit semantics before claiming backend portability. Adopt opaque revision/cursor representations with explicit CLI impact.
4. Agree the directory authorization-snapshot contract and optional provisioning boundary. Preserve the existing role and signing-key ownership.
5. Then specify signed OPTIONS, capability groups, relation names, target resolution, and Unix addressing. Write the normative wire schemas and behavioral conformance scenarios only after those decisions.

The simplest viable starting point is a record-oriented domain API whose mutation owns the complete business operation. Independent providers should be able to implement that API without recreating control's authentication, learning Go interfaces, or coordinating transactions over HTTP.

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
- `pkg/facts/directory/sqlitestore/store.go:561` and `store_test.go:112`: both reviewed and authorized revisions checked during group rebinding.
- `pkg/facts/control/server.go:106`: public authorization and action dispatch; `:257`: managed versus read-only actor lookup.
- `pkg/facts/server/backend.go:29`: private actor/SCIM/management routes and service authorization.
- `pkg/facts/auth.go`: signed actor, request method/target/body binding, and no header-precondition binding.
- `pkg/facts/directory/scim/http.go:52`: current provisioning scope and explicit unsupported operations.

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
