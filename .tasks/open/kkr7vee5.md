---
yatl_version: 1
title: Distinguish service authentication failures from user authentication failures
id: kkr7vee5
created: 2026-09-08T02:35:09.311867Z
updated: 2026-09-08T02:35:09.315346Z
author: Brian McCallister
priority: high
tags:
- api
- security
---

Source: API audit thbfp6pt (.tasks/closed/thbfp6pt.md). User requested high-priority remediation tasks; filing does not implement the proposed changes.

Problem: policy rejects an invalid CA service JWT with 401, CA forwards it publicly, and caclient/broker treat it as an invalid user OIDC token and force a refresh. Refreshing the user cannot repair a rejected CA credential. Inventory already distinguishes these cases at its CA client boundary.

Define explicit error classification across CA, inventory, and policy. User token rejection from inventory must retain the existing user-refresh behavior. Invalid CA-to-service credentials must surface as infrastructure failures, without passing internal status semantics through blindly. Coordinate with the public-error contract task.

Acceptance:
- A policy or inventory service-credential failure does not cause user-token refresh or browser login.
- Actual expired/invalid user authentication still produces the intended single forced-refresh retry.
- Authorization denial remains distinct from authentication and infrastructure failure; retry/failover classification is tested end to end.
- Document the status mapping and preserve request-bound service authentication and distinct service audiences.

---
# Log: 2026-09-08T02:35:09Z Brian McCallister

Created task.
