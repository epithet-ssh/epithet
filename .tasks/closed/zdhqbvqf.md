---
yatl_version: 1
title: Render an absolute AuthorizedPrincipalsCommand path
id: zdhqbvqf
created: 2026-09-03T20:31:07.416890Z
updated: 2026-09-03T20:32:31.666493Z
author: Brian McCallister
priority: critical
tags:
- host-enrollment
- ssh
- freebsd
- release
---

---
# Log: 2026-09-03T20:31:07Z Brian McCallister

Created task.

---
# Log: 2026-09-03T20:31:11Z Brian McCallister

Started working.

---
# Log: 2026-09-03T20:32:31Z Brian McCallister

Closed: Rendered AuthorizedPrincipalsCommand with a visible leading slash and backslash-escaped path delimiters, added regressions, validated against the installed OpenSSH parser, passed the full suite, and cross-built FreeBSD.
