---
yatl_version: 1
title: Fix host-enroll principal-mode CLI initialization
id: 8xxjf6rc
created: 2026-09-03T19:27:01.544135Z
updated: 2026-09-03T19:28:28.348727Z
author: Brian McCallister
priority: high
tags:
- host-enrollment
- cli
- release
---

---
# Log: 2026-09-03T19:27:01Z Brian McCallister

Created task.

---
# Log: 2026-09-03T19:27:04Z Brian McCallister

Started working.

---
# Log: 2026-09-03T19:28:28Z Brian McCallister

Closed: Removed Kong's incompatible enum tag for the OS-dependent default, retained pre-state runtime validation, and added CLI-model and invalid-mode regressions. The original release test and full suite pass.
