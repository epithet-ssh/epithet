---
yatl_version: 1
title: Integrate host enrollment with managed registration
id: pmnvcb0h
created: 2026-09-03T15:34:59.839315Z
updated: 2026-09-03T15:35:38.145546Z
author: Brian McCallister
priority: high
tags:
- epithet-enterprise
- host-enrollment
- security
blocked_by:
- 0rm7n86c
- v6hz0x82
---

Extend `epithet host enroll` with optional managed registration while preserving CA-URL-only bootstrap. When GET of the CA URL advertises one or more host-enrollment Link relations, use the discovered endpoint set, authenticate through the bounded admission mechanism, and register the canonical host ID and enrollment metadata with managed dynamic inventory. When no enrollment relation is advertised, retain the local/static behavior. Acceptance: managed deployments never silently fall back to an unregistered static result; endpoint failure leaves a retryable, coherent enrollment state; duplicate or conflicting host IDs fail closed; endpoint ordering and failover follow the separately defined discovery policy.

---
# Log: 2026-09-03T15:34:59Z Brian McCallister

Created task.
