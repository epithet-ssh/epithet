---
yatl_version: 1
title: Use cursor pagination for directory users and groups
id: mxqw1xmw
created: 2026-09-18T19:11:16.109488Z
updated: 2026-09-18T19:11:26.204240Z
author: Brian McCallister
priority: medium
tags:
- scim
- directory
- storage
---

Replace offset-based storage pagination with a cursor/keyset approach for both directory users and groups. This is deferred work requested during SCIM review; do not optimize only ListUsers and leave ListGroups behind.

The current directory.Store ListUsers/ListGroups methods accept one-based start and count, returning a typed slice and total count from one transaction. sqlitestore.listIDs uses COUNT(*) and ORDER BY id LIMIT/OFFSET, making later pages increasingly expensive.

Design a simple cursor contract for both typed storage operations and evaluate how to serve Elimity's SCIM startIndex/count requests without merely moving the same offset cost into the adapter. Preserve the current Pocket ID flow and required list metadata; assess total-count cost alongside page selection. Keep SQL and cursor mechanics behind the storage boundary, with clear ordering and behavior when provisioning changes occur between pages.

Validate user and group traversal on representative large directories, including partial/empty pages and concurrent mutations. Compare query cost across early and late pages, and rerun the Pocket ID provisioning lifecycle/pagination harness. No implementation changes are part of filing this task.

---
# Log: 2026-09-18T19:11:16Z Brian McCallister

Created task.
