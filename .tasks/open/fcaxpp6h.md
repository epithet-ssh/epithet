---
yatl_version: 1
title: Choose the default principal mode before 1.0
id: fcaxpp6h
created: 2026-09-03T03:47:35.369058Z
updated: 2026-09-06T03:18:13.925844Z
author: Brian McCallister
priority: high
tags:
- principals
- security
- release
---

Before the 1.0 compatibility boundary, decide whether policy.principal-mode should continue defaulting to account-name or switch to the current destination-bound protocol. Evaluate secure-by-default behavior against inventory and target migration costs, document the chosen trust boundary, and update CLI/config defaults and tests atomically if it changes.

---
# Log: 2026-09-03T03:47:35Z Brian McCallister

Created task.

---
# Log: 2026-09-06T03:18:13Z Brian McCallister

Security review 2026-09-05: account-name remains an intentional compatibility mode, but its credentials are reusable for that account on other trusting hosts. Resolve this release decision alongside the confirmed findings in docs/security-review-2026-09-05.md.
