---
yatl_version: 1
title: Register hosts and principal-domain membership
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

Implement the managed registry for host records and their principal-domain
membership. Principal domains are literal, non-secret authorization
identities; possession of a domain name is not authentication. A host without
an explicit domain receives a reserved random per-host domain. A supplied
human-readable domain must already exist and admission must authorize joining
it. Keep host registration identity and canonical names separate from the
domain used for SSH principal derivation, make repeated registration of the
same installation idempotent, and reject conflicting membership requests.
Acceptance: the registry supplies the canonical literal domain and
domain-wide authorization projection used for issuance; proposed host names,
membership, and security labels are not authoritative until an authorized
admission decision.

---
# Log: 2026-09-03T03:25:28Z Brian McCallister

Created task.

---
# Log: 2026-09-03T04:15:25Z Brian McCallister

Design update: replace the earlier generated-host-ID model with host records
that belong to literal principal domains. Named domains are declared and
typo-checked; omission creates a reserved random per-host domain. Possession of
either value is not authentication, and managed registration and membership
must be authorized separately by the enrollment admission mechanism.
