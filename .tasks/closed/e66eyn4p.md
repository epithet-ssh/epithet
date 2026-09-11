---
yatl_version: 1
title: Fix timezone-sensitive certificate deadline assertions
id: e66eyn4p
created: 2026-09-11T19:53:56.438160Z
updated: 2026-09-11T19:54:37.492461Z
author: Brian McCallister
priority: high
tags:
- tests
- release
---

---
# Log: 2026-09-11T19:53:56Z Brian McCallister

Created task.

---
# Log: 2026-09-11T19:54:09Z Brian McCallister

Started working.

---
# Log: 2026-09-11T19:54:37Z Brian McCallister

Closed: Reproduced v0.30.0 release failure under TZ=UTC: deadline assertions compared time.Local with time.UTC after JSON decoding. Replace three struct equality assertions with zero-tolerance WithinDuration to compare exact instants. UTC build/full make test and Pacific affected-package tests passed.
