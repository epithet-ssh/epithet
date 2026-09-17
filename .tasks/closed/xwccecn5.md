---
yatl_version: 1
title: Compare Elimity SCIM adapter with the saved custom implementation
id: xwccecn5
created: 2026-09-17T23:37:19.818564Z
updated: 2026-09-18T19:34:46.572392Z
author: Brian McCallister
priority: high
tags:
- scim
- directory
---

Save the custom SCIM implementation as jj change yvtsntkx (commit 1184d0cb), implement a separate Elimity-based version in wvmtyqpq, and compare both using Ousterhout criteria: information hiding, module depth, cognitive load, change amplification, obscurity, and maintenance ownership. Prefer clean understandable code over preserving speculative edge handling. Use the existing Pocket ID integration and functional tests as compatibility evidence; distinguish actual product requirements from implementation-specific checks. Keep storage, identity, and group-binding behavior stable. Document measured differences and a recommendation, then leave both versions reviewable locally without publishing.

---
# Log: 2026-09-17T23:37:19Z Brian McCallister

Created task.

---
# Log: 2026-09-17T23:37:32Z Brian McCallister

Started working.

---
# Log: 2026-09-17T23:48:24Z Brian McCallister

Saved custom implementation in yvtsntkx at 1184d0cb; implemented a separate Elimity adapter in wvmtyqpq. Protocol implementation shrank from 494 to 241 physical lines, with no storage code changes. Compared information hiding, module depth, change amplification, cognitive load, obscurity, temporal coupling, and maintenance ownership in docs/scim-adapter-comparison.md. Both versions passed full make test and the same Pocket ID lifecycle harness. Observed custom repeated-sync revision 3->3 versus Elimity 3->6. Recorded schema-bound retention, casing, null/trailing-input, pagination metadata, and ETag discovery differences with source review and identical HTTP probes; test expectation changes are explicit. Recommend Elimity for schema-defined Pocket ID use, conditional on accepting or addressing the documented product/protocol differences. No wrapper/fork added to hide library behavior, and no deployment or publishing performed.

---
# Log: 2026-09-17T23:48:24Z Brian McCallister

Closed: Both implementations are saved and reviewable; Elimity is implemented and the Ousterhout comparison, provider results, limitations, and recommendation are documented.

---
# Log: 2026-09-18T00:00:41Z Brian McCallister

Clarified extension scope with the user: the standard enterprise user extension is expected and already registered; no other extensions are currently needed or anticipated soon. Updated the comparison to recommend Elimity for the current requirements without making arbitrary extension retention an outstanding decision. Reassess if a concrete future extension requirement arises; discovery and pagination findings remain separate.

---
# Log: 2026-09-18T00:08:52Z Brian McCallister

User selected the Elimity version as canonical for review. The working copy is already on wvmtyqpq; updated the design and SCIM documentation to record that decision. The custom implementation remains saved in parent change yvtsntkx (1184d0cb). No implementation changes or additional compatibility work.

---
# Log: 2026-09-18T00:33:34Z Brian McCallister

Preserved the adapter comparison here at user request; removed the standalone comparison document from the change.

# SCIM adapter comparison

The Elimity version has the better ownership boundary for Pocket ID provisioning:
protocol definitions and validation belong to the library, while Epithet owns
identity, membership, authorization, and persistence. Elimity is the selected
implementation and the current review baseline. The custom implementation remains
saved in history; the two versions are not behaviorally identical.

The current requirements are core users and groups plus the standard enterprise
user extension, which is already registered in the Elimity adapter. No other
extensions are needed or anticipated soon. Arbitrary extension retention is
therefore not a reason to keep the custom implementation. A concrete future
extension requirement would be a reason to reassess the choice then.

## Versions and scope

- Custom implementation: Jujutsu change `yvtsntkx`, commit `1184d0cb`.
- Elimity implementation: Jujutsu change `wvmtyqpq`, based on that saved change.
- Library: `github.com/elimity-com/scim` pinned to
  `v0.0.0-20260728105928-2641426a1539`.
- Same SQLite backend, storage facade, identity mapping, stable group bindings,
  administrator authorization, configuration, and public endpoint.

The adapter changes from `http.go` plus `document.go` to `http.go` plus
`resource_handler.go`. Physical lines, including comments and whitespace, fall
from **494 to 241** (253 fewer, about 51%). The 126-line storage interface and
554-line SQLite backend have no functional changes. Four modules are added: Elimity and its
three transitive dependencies. These measurements describe maintenance surface,
not a performance result or a complete complexity score.

## Ousterhout assessment

| Criterion | Custom adapter | Elimity adapter | Assessment |
| --- | --- | --- | --- |
| Information hiding | Hides the wire protocol behind `New(Store, token)`, but keeps schema knowledge in a canonical-name registry, validation branches, and discovery definitions. | Keeps the same public interface. Uses built-in schemas for validation and discovery; library types stop at the resource callbacks. | Elimity removes duplicated knowledge rather than merely moving files. |
| Module depth | A genuinely useful module: a small interface hides the protocol. Epithet maintains every hidden mechanism itself. | The library hides routing, schema traversal, pagination parsing, and resource/error formatting behind a schema configuration and callbacks. | Both outer interfaces are deep. Elimity reduces the implementation burden behind ours. |
| Change amplification | Adding a supported complex attribute may require changing canonicalization, validation, and discovery separately. | A standard attribute already covered by the built-in schema needs no adapter change. A supported extension is registered once. | Elimity is stronger for schema-defined evolution. An attribute used for authorization still needs explicit Epithet projection in either design. |
| Cognitive load | A reader follows a large routing function plus a separate document validator, while checking that advertised schemas match behavior. | A reader follows authentication → library validation → one resource callback → one atomic store operation. | The local request flow is easier to explain. Library behavior still requires upstream familiarity. |
| Obscurity | Formatting and edge behavior are directly inspectable locally, although duplication can hide inconsistencies. | Some behavior is surprising: timestamp precision, pagination metadata, and fixed capability advertising required source inspection. | This is Elimity's main cost. Pinning the version and documenting observed differences makes it visible; it does not remove it. |
| Complexity passed to callers | Callers use the owned Store interface and know no SQL or transactions. | Same contract. Callback conversion between our resources and Elimity resources adds some mechanical code. | Essentially equal. The conversion is a deliberate isolation boundary, not a new public abstraction. |
| Temporal coupling | A write enters the store as one complete operation. | Each callback enters the same store once. No pre-read followed by a separate write, mutable global schema configuration, or dependency on rereading the library's request body. | Equivalent transaction ownership; no new synchronization protocol. |
| Maintenance ownership | No new dependency, but protocol fixes and schema expansion are ours indefinitely. | Less owned code and broader built-in schemas, in exchange for a pinned dependency and upstream release review. | Prefer Elimity: its registered schemas cover the current requirements. |

The result is not just fewer lines. In the custom implementation, accepting an
attribute and describing that attribute were separate pieces of knowledge. In
the Elimity implementation they are generated from the same schema definition.
That directly reduces the risk of future changes drifting apart.

There is still adapter code: bearer authentication, endpoint mounting, body
limits, the configured unsupported operations, resource conversion, and error
translation. The callbacks also retain Epithet's requirements for provider
`externalId`, default-active users, no password provisioning, and direct-user
group memberships. These are application decisions and belong here. The store
continues to own uniqueness, member existence, aliases, revisions, and atomicity.

## Observed differences and their relevance

| Behavior | Saved custom implementation | Selected Elimity implementation | Relevance |
| --- | --- | --- | --- |
| Pocket ID lifecycle | Passes. | Passes. | Actual target-provider evidence, including 1,003-user pagination. |
| Immediate repeated sync | Directory revision stayed `3 → 3`. | Revision advanced `3 → 6` through two user PUTs and one group PUT. | Real interaction: Elimity formats timestamps to seconds; Pocket ID's strict `Before` comparison updates on equality. Bindings and identities remain unchanged. No timestamp workaround was added. |
| Unregistered attributes/extensions | Preserved, including large numeric values. | Discarded during schema validation. | Outside current requirements. The expected enterprise user extension is registered and supported. Reassess only when a concrete additional extension is needed. |
| Known attribute casing | Normalizes recognized names, including `schemas` and the enterprise extension key. | Core and subattribute names are case-insensitive, but `schemas` and the enterprise extension key must use their canonical spelling. | Not encountered with Pocket ID; still a limitation for future providers. |
| `itemsPerPage` | Number of resources actually returned. | Requested/clamped page size, even on a short or empty page. | Upstream metadata defect. Pocket ID's tested pagination completes because it also checks the accumulated total and empty pages. This matters before claiming general interoperability. |
| ETag discovery | Advertises ETag support; honors `If-Match`. | Returns resource ETags and honors `If-Match` through our callbacks, but the library hardcodes `etag.supported: false`. | Discovery limitation. A proper upstream option would be preferable to rewriting response bodies. |
| Nulls and extra input | Custom validator rejects explicit `active: null`, trailing JSON, and repeated query parameters. | Null optional attributes are treated as absent; the library decodes the first JSON value and reads the first query value. | Different validation policy, not a reason to recreate the removed defensive parser. Explicit `active: false` still stops issuance and administration. |

These observations use the pinned library source, especially
[resource callbacks and timestamp formatting](https://github.com/elimity-com/scim/blob/2641426a1539/resource_handler.go),
[schema processing](https://github.com/elimity-com/scim/blob/2641426a1539/resource_type.go),
[list handlers](https://github.com/elimity-com/scim/blob/2641426a1539/handlers.go), and
[capability advertising](https://github.com/elimity-com/scim/blob/2641426a1539/service_provider_config.go).
The provider result is measured with Pocket ID v2.14.0, not inferred from those sources.

## Validation and test changes

Both versions passed their full Epithet test suites. The saved version was rerun
in an isolated workspace at `1184d0cb`. The Elimity version also passed explicit
`go build ./cmd/epithet` and `make build`. Both ran the same revised upstream
Pocket ID lifecycle fixture against their actual HTTP handlers and SQLite stores.
It covers create, rename, deactivate/reactivate, group membership, assignment
withdrawal/restoration, deletion, rebinding, and enumeration/deletion over 1,003 users.

The original tests were run against Elimity first, before changing expectations.
They exposed the differences above. The Elimity tests were then changed visibly:

- The extension round-trip assertion now verifies registered-schema behavior and
  explicitly checks that the unknown extension is absent.
- The case-insensitivity test uses canonical schema identifiers while retaining
  uppercase core and nested attribute names.
- Pagination checks actual returned resource counts separately from Elimity's
  reported page-size metadata.
- Custom rejection assertions for null active, trailing JSON, and duplicate query
  parameters were removed; invalid JSON shape, required identity, passwords,
  stale writes, missing members, credentials, and unsupported operations remain covered.
- The shared Pocket ID fixture checks that repeated sync preserves bindings and
  logs revision movement, instead of requiring a no-op revision counter.

Thus “tests pass” does **not** mean the two adapters have identical behavior. It
means the business lifecycle works, with the differing protocol behavior disclosed.
No claim is made about Okta, Entra, production deployment, load, or full SCIM conformance.

## Decision

Use Elimity for the schema-defined Pocket ID integration. It
removes protocol maintenance and gives schema changes a single owner, which is
more valuable than preserving bespoke handling of inputs we have not encountered.

Elimity is now the canonical implementation for review. The known discovery and
pagination limitations remain documented above. Extension support is not an
outstanding decision: the expected enterprise user extension is supported, and
custom extensions are a possible future need. The original implementation remains
saved for comparison. If correcting those limitations requires a large
compatibility wrapper or a maintained fork, reassess: that would put protocol
ownership back in Epithet and weaken this recommendation.


---
# Log: 2026-09-18T00:44:26Z Brian McCallister

Replaced the generic storage Resource/Document/Kind/Page API with explicit User and Group models and typed CRUD/list operations. At user direction, retained only identity, active status, user type, enterprise department/organization, group display name and member IDs, plus storage metadata. Elimity remains at the HTTP boundary; discovery and validation use the supported schema subset, with password recognized only for rejection. Because this feature has never been deployed, replaced the initial SQLite layout directly: separate users and groups tables and one authoritative membership table, without JSON profile storage or a migration path for the discarded development schema. Atomic aliases, audit, revision checks, and user-deletion group ETag updates are preserved. Full make test, make build plus explicit go build, and the Pocket ID v2.14.0 lifecycle harness all pass; harness covers 1,003-user pagination and deletion. Comparison document remains only in this task history.

---
# Log: 2026-09-18T19:12:38Z Brian McCallister

Removed test/pocketid/epithet_test.go.txt, its README, and the documentation link at user request. The upstream-client harness was temporary implementation verification, not permanent repository test infrastructure. The recorded Pocket ID v2.14.0 lifecycle and 1,003-user pagination/deletion results remain valid; no copy of the harness is retained in the current source tree. Epithet-owned automated tests remain in place.

---
# Log: 2026-09-18T19:34:46Z Brian McCallister

Addressed the three accepted external-review findings. Moved storage and administration contracts to pkg/directory (ManagedUser distinguishes stored identities from authorization User facts), removing Elimity/parser dependencies from inventory API, client, and broker. Directory audit now uses an exclusive AuditSequence cursor with a default of 100 and maximum of 1000 events; groups audit exposes --after and --limit and output includes sequence. Existing audit history is retained. Marked GetUser/GetGroup/ListUsers/ListGroups/LookupUser/Bindings transactions read-only while retaining immediate write transactions. Tests cover distinct audit sequences within one revision, new events after a cursor, traversal of a real audit log exceeding the 8 MiB client limit, per-page authorization, and committed snapshot reads while another connection holds an uncommitted write. make test, make build plus explicit go build all pass. Per user direction, no old-layout compatibility guard or commit-message changes were added.
