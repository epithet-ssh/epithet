---
yatl_version: 0
title: 'Auth command: Connection details in templates'
id: njhqwbcg
created: 2025-10-25T12:11:30Z
updated: 2026-01-28T16:27:41.850615Z
priority: medium
tags:
- task
blocked_by:
- e44282c7
---

Pass connection details to auth command for mustache template rendering.

File: pkg/broker/broker.go

Currently auth command templates don't receive connection details (%h, %p, %r, %C).
Add these to the template context so auth commands can use them.

---
## Log

---
# Log: 2026-01-28T16:27:06Z Brian McCallister

Closed, no plan to implement right now
