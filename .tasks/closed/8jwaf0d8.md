---
yatl_version: 1
title: Add SCIM provisioning and persistent group-name bindings
id: 8jwaf0d8
created: 2026-09-05T16:50:06.836671Z
updated: 2026-09-17T23:35:18.861445Z
author: Brian McCallister
priority: high
tags:
- inventory
- scim
- security
blocked_by:
- 512htw8r
---

Implement SCIM provisioning for managed users and groups through the inventory service. Pocket ID is the first end-to-end integration target. Implemented with a directory-owned SQLite store, focused SCIM handlers, coherent authorization snapshots, explicit source selection, and minimal audited group-binding administration.

## Agreed identity contract

- Store both the server-issued SCIM resource id and the provisioning client's externalId.
- For Pocket ID, verified OIDC sub equals SCIM externalId. Resolve authentication through that externalId within the configured provider. The directory owns this mapping and requires an unambiguous lookup.
- Provisioned users require a nonempty, unique externalId within the configured provider. Trusted provisioning may change it: atomically remove the old authentication mapping and establish the new one, retaining the SCIM resource and its memberships. Writ id: matches the new normalized identity. There is no userName/email fallback.
- Epithet's normalized user id, including Writ id: matching, remains the provider identity (Pocket ID sub/externalId). SCIM resource id is internal to provisioning updates, deletes, and membership references; do not change Writ id: to mean SCIM resource id.
- Preserve userName as the mutable human-readable identity. Name-based policy matching intentionally follows renames/name reuse.
- Keep internal resolver/policy user facts plain: id, userName, active, string groups, userType, department, organization. Preserve accepted SCIM documents and extension attributes in storage and translate them at the directory boundary.

## Agreed user lifecycle

- Setting active=false retains the user record and memberships in the managed directory but prevents new certificate grants. Existing active-user requirements for administration continue to apply.
- DELETE actually removes the stored user resource and its membership references atomically; do not retain a soft-deleted user document or user tombstone. Existing audit history is separate from the deleted user resource.
- Deleted users disappear from SCIM queries and subsequent requests for the deleted resource ID return not found. Reprovisioning creates a new SCIM resource ID; old membership references cannot reconnect to it.
- This does not change the separate agreed group-alias tombstone behavior: retired policy names remain reserved until explicit administrative rebinding.

## Agreed group-name binding contract

- Inventory owns durable policy-name aliases bound to immutable SCIM group IDs. Writ remains unaware of SCIM and evaluates human-readable membership strings.
- On group creation, automatically bind the supplied SCIM group name if the policy name has never been claimed. The first successful creation claims the name atomically; provisioning order intentionally determines the winner when names collide.
- Later duplicate names do not fail SCIM provisioning: store the group and its memberships, leave it without a policy alias, and expose the binding conflict through the inventory group listing and audit history. Preserve the existing binding and its membership; duplicate groups gain no membership in that alias. Do not introduce batch-sync coordination to infer an initial sync.
- A SCIM rename preserves the original policy alias. Administration should expose both the policy name and current directory name.
- Deletion retires the binding and preserves its tombstone. A same-name replacement never inherits the alias automatically; explicit, audited administrative rebinding is required.
- Ordinary membership changes flow through automatically. Inventory joins SCIM membership references to bindings and projects policy aliases into user facts.
- Static groups retain their existing literal-name semantics and need no managed binding lifecycle.

## Agreed storage boundary

- Start with modernc.org/sqlite, without a CGO requirement, behind a directory-owned storage facade.
- Hide SQL, transactions, schema migrations, driver-specific failures, and persistence layout from callers. The facade owns the atomic operations the directory needs; callers must not assemble transaction-sensitive sequences themselves.
- Store/retrieve SCIM resources, resolve external identities and memberships, maintain durable aliases, and publish mutations with a coherent directory revision. Authorization reads must observe facts and their revision from one snapshot.
- Replace the resolver's startup-constant directory revision assumption for managed directories. Preserve independently owned host and directory revisions and the CA-mediated service boundary.
- Implement one backend initially. PostgreSQL remains a possible later replacement; migrating host inventory from files to SQLite is future consideration, not part of this scope. Do not add a second persistent cache.
- Validate CGO_ENABLED=0 builds for supported targets and exercise transactional/concurrent/restart behavior natively, including a FreeBSD jail, before treating driver adoption as validated.

## Agreed authentication and source selection

- Pocket ID receives a SCIM endpoint and dedicated bearer provisioning credential, scoped to SCIM users/groups. It conveys neither CA resolution authority, host administration authority, nor explicit policy-alias rebinding authority.
- The bearer token is operator-supplied, either literally in configuration or loaded from a configured secret file. No token-management API is required initially.
- Human administration remains inventory-owned OIDC authorization with configuration-owned administrator grants. Provisioning is asynchronous and never a live dependency of certificate issuance.
- Select one authoritative user directory per deployment: static YAML or managed SCIM. Do not merge sources or fall back to static users when managed records disappear or storage fails. Host inventory selection remains independent.
- Bootstrap SCIM-mode administration by configuring the provisioning credential and administrator provider ID, provisioning that active user, then authenticating normally.
- Operators may explicitly select a static directory in configuration and restart as a recovery path. Static mode must work without opening the managed-directory database. Static authentication still depends on OIDC; this is not identity-provider-independent emergency SSH access.

## Initial management scope and follow-up

Keep first-release management minimal but sufficient to inspect and resolve binding problems:
- List/inspect groups with the SCIM resource ID available for disambiguation, current directory name, policy alias, and bound/conflict/deleted status.
- Provide a basic administrator-authorized way to assign an unbound group a different policy alias or explicitly rebind an existing/retired alias. Record binding changes and collisions in audit history.
- Richer management flows are a fast follow in 1c682zm5, not a prerequisite for the initial integration. Design those flows from experience with the first implementation rather than expanding this milestone.

First-release interoperability targets Pocket ID and standards-correct behavior for the supported SCIM operations. Document and accurately advertise unsupported optional capabilities. Okta is a likely later integration to iterate on, not an initial acceptance requirement.

The SCIM library is an implementation choice. Use elimity-com/scim if it fits cleanly, or implement focused HTTP handlers and API definitions if that is simpler. Keep Epithet-owned interfaces independent of library and database types either way.

## Implemented protocol and operator contract

- Pocket ID v2.14.0 is pinned in the isolated upstream sync harness at test/pocketid. Its actual service runs against Epithet HTTP handlers and SQLite; this is not a production IdP deployment.
- Focused Epithet handlers implement GET/list, POST, PUT replacement, DELETE, discovery, pagination, ETags and If-Match. PATCH, filtering, sorting, bulk, passwords and nested groups are unsupported; optional capabilities are accurately advertised. Accepted additional JSON attributes/extensions are preserved.
- User externalId is required and byte-exact unique; userName is required and Unicode-normalized/case-folded unique. Omitted active defaults true. Lost-create recovery uses list reconciliation by externalId. Group names deliberately are not resource-unique.
- inventory.directory-source selects static (default) or scim; state-dir and either scim-token or scim-token-file configure managed storage/provisioning. state-dir defaults to the native system state directory, with SCIM in directory/directory.db and managed host state under inventory/. Host inventory-source defaults to static; managed enables enrolled hosts. Path overrides do not enable sources. Public SCIM path is /scim/v2. Combined routing exposes SCIM and human management without exposing the private resolver. Directory-only administration does not activate host enrollment.
- directory groups list [--json], bind ALIAS GROUP_ID --revision N, and audit provide the initial management flow. Rebinding checks both the operator-reviewed directory revision and the snapshot used to authorize the OIDC administrator.
- Managed failures fail requests; no stale cache, static fallback, HA replication, or host storage migration was added. Static recovery never opens SQLite or the SCIM secret.
- docs/scim.md documents setup, migration, recovery, lifecycle, credential boundaries, and the supported protocol.

## Implementation sequence and acceptance

1. Finish the outstanding protocol, lifecycle, and configuration contracts; update the specification and interface comments before implementation.
2. Validate modernc on supported targets and implement the managed-directory storage facade, coherent snapshots, identity indexes, membership projection, and durable aliases.
3. Implement scoped provisioning authentication and the selected SCIM HTTP surface.
4. Integrate managed directory resolution, administrator authorization, alias administration, and explicit source selection while preserving CA -> inventory -> policy call ownership. Policy never calls inventory or the database.
5. Validate the Pocket ID lifecycle end to end: initial/repeated sync, pagination, profile/username changes, group membership removal, disabling/deleting users, client assignment removal/reassignment, group rename/collision/deletion/replacement, and explicit rebinding. Verify certificate issuance and administrator authorization, extension round trips, interrupted writes, concurrent reads/writes, restart durability, and static operation without the managed database.
6. Update operator setup/migration/recovery documentation and run repository-required build/test checks. Provisioning changes affect subsequent authorization; do not promise revocation of already issued SSH certificates.

The durable host-storage prerequisite 512htw8r is complete. Existing task wording about SCIM-shaped internal responses, static userName-as-id, and first binding during policy application is superseded by this plan. Keep unrelated Writ follow-ups in 0zj196j0.

---
# Log: 2026-09-05T16:50:06Z Brian McCallister

Created task.

---
# Log: 2026-09-05T16:54:13Z Brian McCallister

Added blocker: 512htw8r

---
# Log: 2026-09-17T21:55:10Z Brian McCallister

Recorded September 17 planning decisions: Pocket ID externalId identity mapping; inventory-owned automatic first-creation group aliases; modernc SQLite behind a directory storage facade; scoped SCIM credential; and explicit static or managed directory selection. Remaining protocol and lifecycle choices are listed separately. Implementation remains unstarted.

---
# Log: 2026-09-17T21:56:54Z Brian McCallister

SCIM adapter boundary agreed: library types/callbacks remain inside the adapter; database types and transactions remain behind the storage facade. Initial source review of elimity-com/scim finds one callback per create/replace/delete and one Patch callback receiving the full operation list, permitting atomic directory mutations. The application still applies PATCH operations, enforces uniqueness and conditional writes, and supplies filtered/paginated results. Schema validation rebuilds attributes from registered definitions and registered extensions; opaque unregistered data preservation is not automatic. Keep the library as a candidate pending executable conformance/Pocket ID tests; no dependency selected or added. Reviewed upstream resource_handler.go, handlers.go, resource_type.go, and schema/schema.go.

---
# Log: 2026-09-17T21:59:06Z Brian McCallister

Agreed collision handling: accept the SCIM group and membership without claiming an occupied alias; show the conflict in inventory listings and audit. Keep initial inspection and explicit alias assignment/rebinding minimal; richer management flows are deferred to 1c682zm5. Library selection remains an implementation choice, including focused Epithet HTTP handlers/API definitions.

---
# Log: 2026-09-17T22:02:09Z Brian McCallister

Agreed required unique externalId and atomic identity remapping on trusted provisioning updates, standards-correct Pocket ID scope (Okta likely later), and an operator-supplied provisioning bearer token. Clarifying SCIM active=false versus DELETE before settling user lifecycle behavior.

---
# Log: 2026-09-17T22:03:17Z Brian McCallister

Agreed user lifecycle: inactive users remain stored with memberships and receive no new certificates; DELETE physically removes the user resource and membership references, rather than soft deletion. Group policy-alias tombstones remain a separate requirement.

---
# Log: 2026-09-17T22:04:31Z Brian McCallister

Started working.

---
# Log: 2026-09-17T22:37:45Z Brian McCallister

Implemented the agreed SCIM directory and minimal administration. Focused handlers support Pocket ID operations, with modernc SQLite isolated behind directory.Store. Added atomic identity/membership/binding/audit updates, coherent authorization revisions, physical user deletion, group alias reservations, explicit source selection and static recovery. Administrator rebinding also checks the authorizing snapshot to reject concurrent revocation. Updated operator docs and Writ spec; richer flows remain in 1c682zm5.

---
# Log: 2026-09-17T22:37:45Z Brian McCallister

Validation passed: make build plus explicit go build; make test; go vet for affected packages; race tests for directory, SCIM, inventory server/client, broker and CLI; CGO_ENABLED=0 builds for Darwin/Linux/FreeBSD amd64 and arm64. Native directory and SCIM tests passed in an existing FreeBSD 15.1 build jail using temporary binaries, including rollback, restart, concurrent snapshots and certificate issuance. Isolated Pocket ID v2.14.0 actual sync service passed initial/repeated sync, profile/active updates, assignment withdrawal/restoration, group lifecycle/rebinding and pagination over 1003 users. No deployed services or live provider configuration changed.

---
# Log: 2026-09-17T22:37:45Z Brian McCallister

Closed: Implemented and validated; operator guide in docs/scim.md and reproducible upstream-client harness in test/pocketid.

---
# Log: 2026-09-17T22:47:05Z Brian McCallister

Moved SCIM management to epithet directory groups list/bind/audit at user request. Host administration remains under epithet inventory. Shared agent transport/profile selection is embedded by both CLI surfaces; service configuration and protocol remain unchanged. Updated setup examples and task description. Explicit go build, make build, make test, and command dispatch smoke tests through a temporary broker socket passed.

---
# Log: 2026-09-17T22:56:13Z Brian McCallister

Addressed configuration review: both management commands now inherit agent.name through the existing Kong agent configuration model, with command-scoped name/flag and broker socket overrides preserved. SCIM server accepts a literal inventory.scim-token or scim-token-file, rejects both in SCIM mode, and retains static recovery without secret/database access. Added annotated examples/inventory-scim.example.yaml, validated with inventory --check using temporary storage. Configuration precedence/token tests and make build/make test passed.

---
# Log: 2026-09-17T23:05:33Z Brian McCallister

Added native system storage defaults shared by directory.db and the managed inventory subdirectory. Introduced explicit inventory-source: managed selection, with static remaining the current default; state-dir is now only a path override. Both combined routing and standalone service use the source selection. Removed client agent settings from the standalone server example; the service never resolves an agent profile or socket. Added regression coverage for store selection/default paths and service independence from invalid agent settings. Build, full make test, and annotated example --check passed. Deferred admin separation is 8rywbj6z; revisiting managed-by-default is 2krqtk0f.

---
# Log: 2026-09-17T23:12:40Z Brian McCallister

Unified managed storage under inventory.state-dir, retaining its native system default. Host state now lives under inventory/ and SCIM SQLite under directory/directory.db; removed directory-db. Source selection remains independent. Updated configuration examples and storage/recovery documentation. Regression checks cover each source independently and both together, static mode avoiding storage, and validation of nested host records. Explicit go build, make build, full make test, and the annotated config --check with one state-dir override all passed.

---
# Log: 2026-09-17T23:18:52Z Brian McCallister

Addressed review by introducing directory.Revision for LookupUser and the Rebind authorization snapshot, updating both implementations and consumers while preserving wire strings. Filed gt3vjk35 for explicit database migrations before the first schema-changing release. Resource/Page naming and CAURL placement remain unchanged pending design discussion; capability discovery retained as explicitly requested. Explicit go build, make build, and full make test passed.

---
# Log: 2026-09-17T23:21:37Z Brian McCallister

Moved CAURL out of the remote inventory ControlResponse and into broker.InventoryResponse. Only the broker adds its discovered CA URL for local CLI enrollment instructions; remote responses do not retain or emit that field. Added coverage for ignoring a remote ca-url, broker-owned token context, ordinary response omission, and local protocol serialization. Explicit build, make build, and full make test passed after correcting the test authentication fixture.

---
# Log: 2026-09-17T23:24:50Z Brian McCallister

Moved SCIM provisioning documents, Resource/Page, storage and binding contracts, and HTTP handling into pkg/directory/scim. The parent directory package now contains only authorization user facts, lookup, and opaque revisions; sqlitestore implements scim.Store. Updated service wiring, management DTO imports, package documentation, and the Pocket ID harness. Provisioning tests now exercise the public SCIM package from scim_test. Explicit go build, make build, full make test, and the isolated Pocket ID v2.14.0 provisioning lifecycle test passed. No protocol or storage-format change.

---
# Log: 2026-09-17T23:35:18Z Brian McCallister

Removed the custom JSON token walker and duplicate-attribute rejection. Standard encoding/json decoding with UseNumber now handles parsing; name normalization is limited to known SCIM attribute objects, preserving unknown extension contents. Existing validation remains. Updated protocol tests for standard decoding, case-insensitive nested fields, and memberships. Explicit go build, make build, full make test, and the isolated Pocket ID lifecycle test passed.
