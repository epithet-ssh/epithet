---
yatl_version: 1
title: Add portable host-ID storage
id: rtz7fxsb
created: 2026-09-03T16:00:51.750979Z
updated: 2026-09-03T16:05:40.715381Z
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

---
# Log: 2026-09-03T16:01:53Z Brian McCallister

Started working.

---
# Log: 2026-09-03T16:05:40Z Brian McCallister

Implemented by Jujutsu change xzzroqmn: platform-specific default paths, strict read-only loading for authorization, atomic no-replace creation for enrollment, explicit file permissions, directory sync, and concurrent-creation coverage.

---
# Log: 2026-09-03T16:05:40Z Brian McCallister

Closed: Portable host-ID path selection and durable idempotent storage are implemented and validated; CA retrieval continues in the next dependent task.
