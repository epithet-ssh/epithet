---
yatl_version: 1
title: Adopt a supported directory database migration framework
id: gt3vjk35
created: 2026-09-17T23:17:57.209112Z
updated: 2026-10-12T14:40:17.201926Z
author: Brian McCallister
priority: high
tags:
- directory
- scim
- storage
---

Choose and introduce a supported directory database migration framework when
product-managed upgrades are needed. Goose is a candidate, not a selected
dependency. Discuss the framework and supported upgrade paths before implementing.

For the current single deployment, the application creates the current schema
and rejects other versions. Existing databases are converted using disposable
external tools, with no migration scripts or bespoke upgrade engine checked into
the repository. PRAGMA user_version is a compatibility guard only.

ADR 0001 uses schema version 2 without historical group bindings. The one-off
version 1 to 2 conversion is external; it does not complete this framework task.
Preserve resources, memberships, audit history, and revision identity when
supported upgrades are introduced. Historical name bindings are intentionally
retired and need not be preserved as live authorization state.

Acceptance for the future work: agree on a framework and ownership model, define
supported source versions and operator procedure, and validate preservation,
restart, migration failure, and rejection of unsupported newer schemas. This work
remains deferred; no migration framework is authorized for the current change.

---
# Log: 2026-09-17T23:17:57Z Brian McCallister

Created task.

---
# Log: 2026-10-12T13:12:55Z Brian McCallister

Started working.

---
# Log: 2026-10-12T13:12:55Z Brian McCallister

Implemented the first schema upgrade as part of ADR 0001: version 1 to 2 drops historical aliases while preserving resources, memberships, revisions, and audit. Preserving bindings is superseded by the approved current-name model. Added upgrade, reopen, newer-version, and failed-migration rollback tests; operator procedure is in pkg/facts/directory/README.md.

---
# Log: 2026-10-12T13:16:07Z Brian McCallister

Closed: Implemented ADR 0001 and the transactional directory schema upgrade; make -B build and make test pass.

---
# Log: 2026-10-12T14:39:42Z Brian McCallister

Reopened.

---
# Log: 2026-10-12T14:40:17Z Brian McCallister

Reopened after review: removed the embedded startup migration. Use disposable external tooling for the single deployment; defer framework selection, potentially Goose. Current-schema creation and unsupported-version rejection remain in the application.
