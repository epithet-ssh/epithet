---
yatl_version: 1
title: Define public CA errors and keep internal diagnostics in server logs
id: ms54kqbp
created: 2026-09-08T02:35:09.301204Z
updated: 2026-09-11T03:27:48.601839Z
author: Brian McCallister
priority: high
tags:
- api
- security
---

Source: API audit thbfp6pt (.tasks/closed/thbfp6pt.md). User requested high-priority remediation tasks; filing does not implement the proposed changes.

Problem: CA forwards private policy response bodies and statuses verbatim. Other failures expose backend URLs or raw discovery/transport diagnostics. The audit reproduced a synthetic internal path in a public 500 response. Successful issuance already returns only a certificate; preserve that boundary.

Scope: pkg/ca/ca.go, pkg/caserver/caserver.go, pkg/caclient, and public API documentation. Define the client-visible error contract, including which policy-denial detail is intentionally public. Keep raw backend diagnostics and private topology in server logs. Do not assume all upstream messages are safe for clients. Coordinate status classification with the separate service-authentication task.

Acceptance:
- Inventory/policy transport and internal failures produce appropriate public infrastructure errors without backend URLs, filesystem paths, or raw upstream diagnostics.
- Public errors remain useful and consistent with client retry/failover behavior; intentional denial messages follow the documented contract.
- Regression coverage includes issuance and discovery error paths plus unchanged certificate-only success responses.
- Audit metadata and revisions stay in private logs, not public payloads or certificates.

---
# Log: 2026-09-08T02:35:09Z Brian McCallister

Created task.

---
# Log: 2026-09-11T03:15:04Z Brian McCallister

Started working.

---
# Log: 2026-09-11T03:27:48Z Brian McCallister

Closed: Define fixed public CA messages and trusted CA error classes. Keep policy denial/pending reasons, private URLs, and diagnostics in server logs; sanitize issuance and discovery failures, and preserve certificate-only success. Document status mappings and coordinated migration in docs/ca-errors.md and docs/inventory-cleanup-summary.md. make build, explicit go build, full make test, and broker/breakerpool race checks passed.
