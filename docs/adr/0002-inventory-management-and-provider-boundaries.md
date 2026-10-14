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

Enrollment POST carries a host and optional enrollment credential. Status derives
from authority: unauthenticated enrollment through control creates pending state;
a valid single-use credential activates its reservation; an authorized admin can
create an active pattern. A pattern alone never conveys administrative authority.
Existing lifecycle, name/realm constraints and deletion semantics remain.

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
SCIM protocol handling, and directory stores own atomic mutations and audit.
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
before review. Pagination retains bounded ID/sequence continuation without adding
cross-page snapshot semantics. The SQLite schema remains unchanged.

The [inventory package contract](../../pkg/facts/inventory/README.md) documents
wire shapes and adapter responsibilities. YATL `s9cqey45` retains planning and
discussion history; this ADR records the reasons for the design.
