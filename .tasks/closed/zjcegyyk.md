---
yatl_version: 1
title: Add HTTP caching headers to policy server discovery endpoint
id: zjcegyyk
created: 2025-12-27T18:32:29.038986Z
updated: 2025-12-27T19:04:02.612656Z
author: Brian McCallister
priority: medium
tags:
- feature
---

---
# Log: 2025-12-27T18:32:29Z Brian McCallister

Created task.

---
# Log: 2025-12-27T19:02:28Z Brian McCallister

Started working.

---
# Log: 2025-12-27T19:02:28Z Brian McCallister

Starting implementation: redirect pattern for discovery caching

---
# Log: 2025-12-27T19:04:02Z Brian McCallister

Closed: Implemented discovery URL redirect pattern: /d/current redirects to /d/{hash} with 5-min cache
