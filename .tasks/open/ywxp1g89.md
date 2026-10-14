---
yatl_version: 1
title: Design SCIM directory management and CLI access through control
id: ywxp1g89
created: 2026-10-13T15:43:29.263132Z
updated: 2026-10-14T09:38:48.667320Z
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
Manual directory user creation/editing on the CLI remains deferred, lower-priority
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
  the built-in root for existing snapshots/listing/audit, separate from SCIM.
- The built-in SCIM subset, identity mapping, schema and database are unchanged.
  Directory CLI commands and the identity/setup questions below remain deferred.

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
  The server still assigns a separate SCIM resource ID.

## Identity mapping and deferred CLI discussion

Manual creation only works when the chosen ID equals the verified OIDC claim
used for directory lookup. Existing options include stable-id (sub by default,
Entra oid by default), verified-email, and an explicit top-level user-id-claim.
Defaulting ID to NAME is meaningful only when that value matches the configured
mapping. Operator setup and documentation need further discussion; no new mapping
or enrollment workflow was agreed. An invite flow was explicitly NOT proposed
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
directory CRUD was rejected because it duplicates the standard. Existing signed
actor snapshot and directory audit/listing protocols remain: their removal was
not authorized by this implementation.

## Design record

The user requested discussion followed by ADR 0002 for the settled management
interface, alternatives and rationale. ADR 0002 now records the settled inventory
and SCIM provider boundaries; deferred directory CLI work must not block either.
Implementation planning and sequencing stay in YATL.

The original combined exploration and conversation log remain in the history of
`s9cqey45`. Its older binding proposals were superseded by ADR 0001 and the SCIM
boundary above.

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
