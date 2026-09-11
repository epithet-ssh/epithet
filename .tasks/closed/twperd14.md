---
yatl_version: 1
title: Define supported public behavior for pending policy decisions
id: twperd14
created: 2026-09-08T02:35:09.359650Z
updated: 2026-09-11T03:27:48.624197Z
author: Brian McCallister
priority: high
tags:
- api
- architecture
---

Source: API audit thbfp6pt (.tasks/closed/thbfp6pt.md). User requested high-priority remediation tasks; filing does not implement the proposed changes.

Extracted from Writ follow-up 0zj196j0; this task owns public pending-response handling.

Problem: the library evaluator can return 202 with plain text, CA forwards it, and caclient treats it as InvalidRequestError. The built-in CLI currently cannot register requirement plugins, so this is not an active static CLI workflow and must not be advertised as a supported pending protocol.

Decide and document the public behavior for pending decisions. Either represent unsupported pending behavior honestly for now or define an intentionally bounded client contract. Do not introduce stateful signup, approval storage, polling, or new plugin execution capabilities merely to clean up these APIs; those require separate scope.

Acceptance:
- CA and client agree on the meaning of any exposed pending status and do not misclassify it as malformed input, successful issuance, or an expired user token.
- Pending results never mint a certificate and have tested client behavior.
- API docs distinguish implemented behavior from future plugin/approval workflows.
- Coordinate error/status mapping with the public-error and service-authentication tasks.

---
# Log: 2026-09-08T02:35:09Z Brian McCallister

Created task.

---
# Log: 2026-09-11T03:17:00Z Brian McCallister

Started working.

---
# Log: 2026-09-11T03:27:48Z Brian McCallister

Closed: User requested a pending outcome without descriptive policy leakage. Implement generic public 202 authorization pending; try again later and caclient.PolicyPendingError. No cert, forced refresh, automatic polling, or failover; later explicit requests retry. Fix breaker recovery to preserve non-infrastructure outcomes. Document CLI plugin limitations, no approval store or retry-delay protocol, and client migration. Full suite, recovery regressions, and broker/breakerpool race checks passed.
