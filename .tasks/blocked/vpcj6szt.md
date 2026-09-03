---
yatl_version: 1
title: Register generated host identities
id: vpcj6szt
created: 2026-09-03T03:25:28.969057Z
updated: 2026-09-03T15:35:38.139957Z
author: Brian McCallister
priority: critical
tags:
- epithet-enterprise
- host-enrollment
- security
blocked_by:
- 548x7rsk
---

Implement the managed registry for canonical generated host IDs. The host ID is a stable, non-secret identifier and possession of it is not authentication; registration and mutation are authorized separately through the enrollment admission mechanism. Bind canonical names and aliases separately from admission, make repeated registration of the same installation idempotent, and reject conflicting reuse of one host ID by independent enrollment requests. Acceptance: the registry supplies canonical host-ID and principal-issuance metadata; proposed names and security labels are not authoritative until an authorized admission decision.

---
# Log: 2026-09-03T03:25:28Z Brian McCallister

Created task.

---
# Log: 2026-09-03T04:15:25Z Brian McCallister

Design update: the registered identifier is a generated, non-secret host ID rather than an SSH host public key. Possession of the ID is not authentication; managed registration must be authorized separately by the enrollment admission mechanism. Rewrite this task before implementation to remove designated-key proof-of-possession assumptions.
