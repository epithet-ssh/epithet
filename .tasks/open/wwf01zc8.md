---
yatl_version: 1
title: Support multiple Writ policy files
id: wwf01zc8
created: 2026-09-29T02:41:52.309730Z
updated: 2026-09-29T02:42:47.868189Z
author: Brian McCallister
priority: medium
---

Support supplying multiple Writ policy files for CA startup and offline policy validation. Brian confirmed this requirement while reorganizing cmd/epithet; it replaces the review note previously checked into PolicyConfig. Agree on how policies combine, ordering, and cross-file diagnostics before implementation. Keep both policy validation and CA startup on the same loading path, with CLI flags remaining canonical for configuration.

---
# Log: 2026-09-29T02:41:52Z Brian McCallister

Created task.
