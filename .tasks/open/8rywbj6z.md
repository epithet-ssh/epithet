---
yatl_version: 1
title: Separate directory and host inventory administration
id: 8rywbj6z
created: 2026-09-17T23:00:17.939229Z
updated: 2026-09-17T23:00:30.784146Z
author: Brian McCallister
priority: medium
tags:
- inventory
- directory
- administration
---

Separate directory administration from host inventory administration after the initial SCIM implementation. Requested during review of 8jwaf0d8; this is deferred work, not part of the current defaults/configuration correction.

The CLI already distinguishes `epithet directory` from `epithet inventory` management commands, but they share service configuration, a management endpoint/dispatcher, and one inventory-admin grant covering both domains. Review those boundaries and separate the directory and host administrative responsibilities so each has clear configuration and ownership. Decide the concrete authorization and transport changes before implementation; a separate process or new roles are not predetermined.

Keep server configuration distinct from management-client configuration. The inventory/directory service must not need a local agent name or socket. Only client management commands use agent profile discovery. Preserve the CA -> inventory -> policy issuance topology unless a separately agreed change requires otherwise.

Acceptance: agree and implement the focused configuration/API/authorization split, update operator documentation, and test the resulting authority boundaries. Do not broaden this task into the richer group-management UX already tracked in 1c682zm5.

---
# Log: 2026-09-17T23:00:17Z Brian McCallister

Created task.
