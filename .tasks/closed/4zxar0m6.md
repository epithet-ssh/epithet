---
yatl_version: 1
title: Store dynamic inventory per item with indexed hostname resolution
id: 4zxar0m6
created: 2026-09-13T00:17:44.946432Z
updated: 2026-09-13T00:29:32.908204Z
author: Brian McCallister
priority: high
tags:
- inventory
- storage
---

---
# Log: 2026-09-13T00:17:44Z Brian McCallister

Created task.

---
# Log: 2026-09-13T00:19:44Z Brian McCallister

Started working.

---
# Log: 2026-09-13T00:29:32Z Brian McCallister

Implemented records/<literal-id>.yaml with atomic exclusive creation and same-file token redemption. Added startup-built name, credential, domain, and record indexes; per-item audit and retired-name claims; validated legacy snapshot migration with preserved backup and revoked legacy tokens. Documented offline repair and snapshot semantics. Validation passed: make build (no-op), explicit native build, make test, inventory/server/broker race tests, final inventory and server integration checks, and FreeBSD amd64 cross-build.

---
# Log: 2026-09-13T00:29:32Z Brian McCallister

Closed: Implemented and validated per-item persistence and indexed resolution.
