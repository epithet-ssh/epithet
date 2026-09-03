---
yatl_version: 1
title: Choose the default principal mode before 1.0
id: fcaxpp6h
created: 2026-09-03T03:47:35.369058Z
updated: 2026-09-03T03:47:40.273648Z
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
