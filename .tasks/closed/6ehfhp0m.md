---
yatl_version: 1
title: Issue principals using configured host modes
id: 6ehfhp0m
created: 2026-09-03T03:25:05.002896Z
updated: 2026-09-03T03:26:17.350054Z
author: Brian McCallister
priority: critical
tags:
- security
- inventory
- principals
blocked_by:
- 41xjh97q
---

Add deployment-default and exact-host or pattern principal modes, static exact-host identity keys, and destination-bound issuance after authorization. Acceptance: account-name remains the compatibility default; destination-bound exact hosts require valid keys; static patterns cannot use a shared identity key but can explicitly fall back; unknown or incomplete configuration fails closed. Implemented by jj change ktkukzqs.

---
# Log: 2026-09-03T03:25:05Z Brian McCallister

Created task.

---
# Log: 2026-09-03T03:26:17Z Brian McCallister

Closed: Implemented and validated in the destination-bound principal Jujutsu stack.
