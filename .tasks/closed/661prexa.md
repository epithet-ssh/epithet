---
yatl_version: 1
title: Support multiple DNS names for one inventory host
id: 661prexa
created: 2026-09-11T18:24:13.924756Z
updated: 2026-09-11T18:35:49.680548Z
author: Brian McCallister
priority: high
tags:
- inventory
- api
- authorization
---

Support peer DNS names on one static host record via names; require names even for a single name and reject the singular name field. Resolve every name to the same labels, accounts, and principal domain. Carry names through inventory and policy facts; exact and glob host matchers match any registered name, with negation applied to the whole host match, so switching names cannot evade a deny. Preserve shared principal-domain policy projection and request target binding. Reject ambiguous names across records. Record opaque, immutable inventory-assigned host IDs for future dynamic storage, separate from DNS names, credentials, and principal domains; do not add static IDs or implement a database. Update documentation and meaningful tests, validate build/full suite, and save in jj.

---
# Log: 2026-09-11T18:24:13Z Brian McCallister

Created task.

---
# Log: 2026-09-11T18:24:57Z Brian McCallister

Started working.

---
# Log: 2026-09-11T18:35:49Z Brian McCallister

Closed: Implemented peer DNS names throughout static inventory, resolver and policy facts, and Writ evaluation. Require names even for singleton hosts; reject singular name. Added name-collision, binding, whole-host allow/deny and certificate regression coverage. Updated examples, API docs, and future immutable host ID plans. Build, full make test, and fresh server integration passed.
