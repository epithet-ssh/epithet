---
yatl_version: 1
title: Separate directory and host inventory administration
id: 8rywbj6z
created: 2026-09-17T23:00:17.939229Z
updated: 2026-09-27T22:07:34.138521Z
author: Brian McCallister
priority: medium
tags:
- inventory
- directory
- administration
---

Separate directory and host inventory administration using the agreed service topology in docs/service-topology-options.md, consolidated September 23, 2026. Design direction is agreed; implementation remains paused pending the remaining contract discussion and an implementation request.

CA combines issuance authentication, fact gathering, Writ evaluation and signing. A separate epithet-control process owns administration, SCIM provisioning and enrollment entry points. Directory and inventory own facts, mutation rules, revisions, persistence and audit. Custom fact providers retain small read-only replacement contracts.

CA -> facts is a separate contract from control-plane APIs. Directory lookup uses id and returns an active user object with HTTP 200, or HTTP 404 for unknown/inactive users; no active field or nullable success response. Both fact responses may include revision as an optional opaque string, limited to 256 UTF-8 bytes, logged as structured metadata alongside the lookup. It has no comparison, ordering, caching or authorization semantics. Omission is normal and generates no substitute; non-string or oversized values invalidate the response. Remove mandatory source-revision requirements; providers need no global counter or snapshot-version semantics. This supersedes removing revision metadata entirely. Control-plane mutation revisions and the directory-rebinding check remain distinct. Host response shape and optional user-field defaults remain to be settled.

Control always runs separately: the combined server launches it alongside CA and the fact services; independently managed deployments run it explicitly. Preserve the combined launcher's shared lifecycle as a legitimate small-deployment choice. CA advertises control through a Link header; the public router sends management traffic directly to control.

Control enforces independent directory-administrator and inventory-administrator roles from configured user IDs or directory groups, requiring an active directory user. It has a persistent configured signing key; fact services receive the public key out of band. CA credentials permit fact reads, not administration. Human administrative requests carry a short-lived, request-bound control JWT with the actor as sub; the request identifies the operation, so there is no separate operation claim.

Preserve backend mutation/audit ownership and the directory-rebinding authorization-revision check. SCIM keeps its existing operator-supplied random bearer token, validated by control, which signs the downstream request to directory. Preserve existing freshness/replay semantics, including the 60-second service-token lifetime and revision checks; no new replay or revocation mechanism is included. Enrollment validation ownership and non-human audit provenance remain to be finalized as described in the design document. Refactor first, optimize second: preserve listing behavior and defer pagination/enumeration optimization. Task mxqw1xmw remains deferred and is not a dependency of this refactor.

This supersedes the previous task note preserving CA -> inventory -> policy and leaving separate roles/processes undecided. Keep server configuration distinct from management-client agent profiles and sockets. Richer group-management UX remains in 1c682zm5. No new recovery workflow, compatibility mode, or credential provisioning mechanism is included.

Acceptance: implement the agreed configuration/API/authorization split when requested, update operator documentation, and validate authority boundaries, SCIM/enrollment flows, mixed built-in/custom providers, and both deployment arrangements using the design document's validation section.

---
# Log: 2026-09-17T23:00:17Z Brian McCallister

Created task.
