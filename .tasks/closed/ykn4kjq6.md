---
yatl_version: 1
title: Add offline target principal validation
id: ykn4kjq6
created: 2026-09-03T03:24:46.990386Z
updated: 2026-09-03T03:26:17.333212Z
author: Brian McCallister
priority: critical
tags:
- security
- ssh
- principals
blocked_by:
- p7qrspc2
---

Add epithet host authorized-principals as an offline sshd AuthorizedPrincipalsCommand consumer of pkg/principal. Accept repeatable designated public-key files for planned rotation, reject malformed keys and certificates, deduplicate output, and provide an explicit temporary account-name overlap flag for migration. Acceptance: output is computed before writing and the command never contacts the control plane. Implemented by jj change qostsnvm.

---
# Log: 2026-09-03T03:24:46Z Brian McCallister

Created task.

---
# Log: 2026-09-03T03:26:17Z Brian McCallister

Closed: Implemented and validated in the destination-bound principal Jujutsu stack.
