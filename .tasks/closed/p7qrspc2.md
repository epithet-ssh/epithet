---
yatl_version: 1
title: Specify and derive destination-bound principals
id: p7qrspc2
created: 2026-09-03T03:24:38.531728Z
updated: 2026-09-03T03:26:17.302432Z
author: Brian McCallister
priority: critical
tags:
- security
- ssh
- principals
---

Specify epithet-principal-v1 as an Epithet issuance protocol outside Writ, implement it in public pkg/principal, and publish byte-level normative vectors. Acceptance: SSH-string framing is exact; canonical public-key blobs ignore authorized-key text differences; account bytes are not normalized; the complete SHA-256 digest is emitted as unpadded base64url. Implemented by jj changes smkoxotk and oyvtqlmr.

---
# Log: 2026-09-03T03:24:38Z Brian McCallister

Created task.

---
# Log: 2026-09-03T03:26:17Z Brian McCallister

Closed: Implemented and validated in the destination-bound principal Jujutsu stack.
