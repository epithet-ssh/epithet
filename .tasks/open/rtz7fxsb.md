---
yatl_version: 1
title: Add portable host-ID storage
id: rtz7fxsb
created: 2026-09-03T16:00:51.750979Z
updated: 2026-09-03T16:00:58.904444Z
author: Brian McCallister
priority: high
tags:
- host-enrollment
- portability
- security
blocked_by:
- 0rm7n86c
---

Implement reusable local storage for canonical host IDs without exposing a partial enrollment command. Choose the default state directory from an explicit runtime.GOOS policy: `/var/lib/epithet` on Linux, `/var/db/epithet` on FreeBSD/OpenBSD/NetBSD/DragonFly, `/var/opt/epithet` on Solaris/illumos, and the native system application-state location on other supported systems. Allow an enrollment-time path override. Create the ID durably without overwriting an existing file; read an existing canonical ID idempotently; malformed state is a hard error; the file is non-secret but only root may modify it and the AuthorizedPrincipalsCommand user must be able to read it.

---
# Log: 2026-09-03T16:00:51Z Brian McCallister

Created task.
