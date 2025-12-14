---
title: 'Auth command: Connection details in templates'
id: njhqwbcg
created: 2025-10-25T12:11:30Z
updated: 2025-12-14T17:39:45.593974Z
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

