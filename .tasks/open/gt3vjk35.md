---
yatl_version: 1
title: Add explicit directory database migrations before the first schema-changing release
id: gt3vjk35
created: 2026-09-17T23:17:57.209112Z
updated: 2026-09-17T23:18:07.995207Z
author: Brian McCallister
priority: high
tags:
- directory
- scim
- storage
---

Introduce explicit, versioned SQLite directory schema upgrades before the first release that changes the initial schema. Requested in review of 8jwaf0d8. Today pkg/directory/sqlitestore/store.go initializes version 1 and rejects unsupported PRAGMA user_version values; it has no upgrade path. Keep this work deferred until that schema-changing release. Define and implement ordered migrations owned by the SQLite store, preserving existing resources, memberships, policy-name bindings, audit history, and revision identity. Specify failure and restart behavior, reject databases newer than the binary supports, and document the operator upgrade procedure. Validate upgrades from the previously released schema with representative data, opening an already-current database, and a failed migration leaving a usable prior state. Do not implement migrations as part of the current review.

---
# Log: 2026-09-17T23:17:57Z Brian McCallister

Created task.
