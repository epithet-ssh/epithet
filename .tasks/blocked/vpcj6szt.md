---
yatl_version: 1
title: Register host identities with proof of possession
id: vpcj6szt
created: 2026-09-03T03:25:28.969057Z
updated: 2026-09-03T03:25:34.613781Z
author: Brian McCallister
priority: critical
tags:
- epithet-enterprise
- host-enrollment
- security
blocked_by:
- 548x7rsk
---

Implement the managed host identity registry around one designated SSH host public key. Require nonce-based proof of possession, bind canonical names and aliases separately from admission, and reject one fingerprint becoming multiple independent host identities. Acceptance: the registry supplies the complete canonical key and principal issuance metadata; proposed names and security labels are not authoritative until an authorized admission decision.

---
# Log: 2026-09-03T03:25:28Z Brian McCallister

Created task.
