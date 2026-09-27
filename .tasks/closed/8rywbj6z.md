---
yatl_version: 1
title: Separate directory and host inventory administration
id: 8rywbj6z
created: 2026-09-17T23:00:17.939229Z
updated: 2026-09-27T23:32:07.852700Z
author: Brian McCallister
priority: medium
tags:
- inventory
- directory
- administration
---

Implemented the agreed topology in docs/service-topology-options.md. CA owns OIDC authentication, independent directory/inventory fact reads, local Writ evaluation, and signing. Control is a separate process with its own configured persistent key; it authorizes independent directory/inventory admin roles and forwards signed requests carrying human actor identity. Backends retain storage, mutation invariants, transactional directory-rebinding authorization revisions, and audit.

CA-to-facts uses signed GET /lookup?id=... and GET /lookup?host=..., no body, no cache, active objects or 404. User id is required and userName/attributes/groups are optional. Host names/accounts/structured principal are required. Principal domains remain opaque and separate from host names. Revisions are optional opaque logging strings of at most 256 UTF-8 bytes, with no authorization or cache semantics. The signature binds the complete query.

Existing public control operations were ported without redesigning their API. SCIM keeps its random bearer credential at control and its backend audit provenance. Enrollment tokens create empty pending host records; valid redemption fills and activates the same record atomically. Pending status alone grants nothing. Empty reservations cannot be approved or supply certificate facts, and denial/removal/revocation prevents redemption. The storage loader rejects older token-only records; active host records and SCIM storage retain their formats. Migration and new configuration are documented in docs/inventory.md.

The combined server supervises separate CA, control, directory, inventory, and router processes. Independent service launch remains supported. CA advertises control through a Link header. Bespoke fact providers implement only the small lookup API; custom directory facts work with built-in inventory administration.

Validation covers separate roles/keys/actor attribution, SCIM lifecycle through signed control calls, enrollment reservation lifecycle and restart/failure paths, optional fact fields and revisions, request-bound query authentication, mixed custom/built-in providers, combined-process shutdown, real OIDC, and SSH issuance. Required make build and make test plus relevant race checks pass.

Control API redesign and pagination/enumeration optimization remain deferred. Task mxqw1xmw is not a dependency; richer group-management UX remains in 1c682zm5. No automatic key provisioning, new replay database, or fallback/recovery mode was introduced.

---
# Log: 2026-09-17T23:00:17Z Brian McCallister

Created task.

---
# Log: 2026-09-27T23:32:07Z Brian McCallister

Closed: Implemented separate control and fact services, in-process CA policy, and pending host reservations; build, full suite, and relevant race checks pass.
