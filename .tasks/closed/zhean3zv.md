---
yatl_version: 1
title: 'Link-header auth discovery: CA advertises auth config via relative Link on GET /, broker resolves it instead of hardcoding /discovery. Spec: adr/link-header-auth-discovery.md'
id: zhean3zv
created: 2026-08-17T08:16:44.337551Z
updated: 2026-09-29T17:20:21.677638735Z
author: Brian McCallister
priority: medium
---

---
# Log: 2026-08-17T08:16:44Z Brian McCallister

Created task.

---
# Log: 2026-09-29T17:20:21Z Brian McCallister

Closed: Implemented: CA advertises relative auth discovery Link; client follows it with prefix handling, redirect resolution, and same-origin checks. Documentation and regression tests are present. go test -race ./pkg/caclient ./pkg/caserver passes. Closure approved by Brian.
