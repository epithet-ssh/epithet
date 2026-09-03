---
yatl_version: 1
title: Verify and document hashed-principal deployment
id: va3jrtx4
created: 2026-09-03T03:25:12.412834Z
updated: 2026-09-03T03:26:17.357435Z
author: Brian McCallister
priority: critical
tags:
- security
- ssh
- documentation
blocked_by:
- 6ehfhp0m
---

Prove the destination boundary with live OpenSSH and document static-inventory configuration, target installation, migration overlap, aliases, and the remaining managed-inventory limitations. Acceptance: a certificate derived for host A is accepted there and rejected by host B with another key; examples validate; the Writ spec states only the authorization boundary and does not specify principal encoding. Implemented by jj changes oopqkszv and tulosltn.

---
# Log: 2026-09-03T03:25:12Z Brian McCallister

Created task.

---
# Log: 2026-09-03T03:26:17Z Brian McCallister

Closed: Implemented and validated in the destination-bound principal Jujutsu stack.
