---
yatl_version: 1
title: Include inventory user IDs in certificate issuance logs
id: gaxh54pf
created: 2026-09-07T16:30:16.921189Z
updated: 2026-09-07T16:33:48.425588Z
author: Brian McCallister
priority: medium
tags:
- identity
- logging
---

Carry the resolved inventory id as policy-response audit metadata to the CA. Certificate issuance logs use the inventory names id and userName. Keep certificate Key ID as userName. Verify propagation through local OIDC-to-CA issuance, including subject/oid/email modes, inventory renames, and absence of the former log keys identity and user_id.

---
# Log: 2026-09-07T16:30:16Z Brian McCallister

Created task.

---
# Log: 2026-09-07T16:31:02Z Brian McCallister

Started working.

---
# Log: 2026-09-07T16:31:37Z Brian McCallister

Added policy-response user_id audit metadata from the resolved inventory record, propagated into CertEvent and the structured certificate issued log alongside identity. Certificate Key ID remains userName. Existing issuer/subject/oid/email integration tests now assert logged IDs and usernames and reject token-supplied user_id substitution; rename tests preserve logged inventory ID. make build (no-op), explicit go build ./cmd/epithet and full make test passed.

---
# Log: 2026-09-07T16:31:37Z Brian McCallister

Closed.

---
# Log: 2026-09-07T16:33:48Z Brian McCallister

Aligned issuance-log fields with inventory names: id and userName, replacing identity and user_id. Renamed audit event fields and the newly added policy-response ID accordingly. Certificate Key ID still comes from userName. Updated integration assertions, documentation and task description. Rebuilt and full make test passed.
