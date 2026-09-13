---
yatl_version: 1
title: Remove unreleased inventory storage compatibility
id: f7dv5w7a
created: 2026-09-13T03:48:31.129816Z
updated: 2026-09-13T03:51:52.397396Z
author: Brian McCallister
priority: high
tags:
- inventory
- review
---

---
# Log: 2026-09-13T03:48:31Z Brian McCallister

Created task.

---
# Log: 2026-09-13T03:49:24Z Brian McCallister

Started working.

---
# Log: 2026-09-13T03:51:52Z Brian McCallister

Deleted all unreleased single-file migration, legacy metadata, old ID support, and associated tests/docs. Removed degraded startup: configured dynamic storage must load and validate successfully, otherwise startup fails and releases the lock. Static-only operation requires state-dir unset. Validated with go fmt, make build and explicit native/FreeBSD builds, make test, inventory/broker race tests, and uncached combined-server integration.

---
# Log: 2026-09-13T03:51:52Z Brian McCallister

Closed: Removed compatibility and required configured storage to succeed at startup.
