---
yatl_version: 1
title: Integrate host enrollment with managed registration
id: pmnvcb0h
created: 2026-09-03T15:34:59.839315Z
updated: 2026-09-03T16:01:13.297985Z
author: Brian McCallister
priority: high
tags:
- epithet-enterprise
- host-enrollment
- security
blocked_by:
- v6hz0x82
- 930f5gpq
---

Extend `epithet host enroll` with optional managed registration while preserving
CA-URL-only bootstrap. When GET of the CA URL advertises one or more inventory
host-enrollment Link relations, use the discovered endpoint set, authenticate
through the bounded admission mechanism, and register the host plus its
principal-domain membership. With no `--domain`, create a reserved random
per-host domain. With `--domain NAME`, resolve an already-declared named domain
and reject unknown names without creating anything. When no enrollment
relation is advertised, retain local/static generated-domain behavior and do
not accept `--domain`. Acceptance: managed deployments never silently fall
back to an unregistered static result; endpoint failure leaves a retryable,
coherent enrollment state; conflicting host records or domain memberships fail
closed; endpoint ordering and failover follow the separately defined discovery
policy.

---
# Log: 2026-09-03T15:34:59Z Brian McCallister

Created task.

---
# Log: 2026-09-03T16:01:13Z Brian McCallister

Removed blocker: 0rm7n86c

---
# Log: 2026-09-03T16:01:13Z Brian McCallister

Added blocker: 930f5gpq
