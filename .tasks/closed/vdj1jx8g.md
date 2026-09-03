---
yatl_version: 1
title: Fetch and install the CA key during host enrollment
id: vdj1jx8g
created: 2026-09-03T16:00:58.912309Z
updated: 2026-09-03T16:23:53.891461Z
author: Brian McCallister
priority: high
tags:
- host-enrollment
- ssh
blocked_by:
- rtz7fxsb
---

Add `epithet host enroll --ca-url <url>` as the privileged local-enrollment entry point, with the CA URL as its only required bootstrap input. GET the CA URL, validate the response as the SSH CA public key, and install it durably at the selected platform-appropriate or enrollment-overridden path. Preserve any advertised Link headers for later managed-registration integration. Acceptance: reruns are idempotent; a conflicting CA key is a hard error unless an explicit replacement workflow is selected; failed retrieval or validation leaves existing host state unchanged.

---
# Log: 2026-09-03T16:00:58Z Brian McCallister

Created task.

---
# Log: 2026-09-03T16:11:46Z Brian McCallister

Started working.

---
# Log: 2026-09-03T16:23:53Z Brian McCallister

Closed: Implemented host enroll CA bootstrap: strict CA-root key validation, durable non-replacing epithet-ca.pub installation beside the canonical host ID, idempotent reruns, preserved Link fields, portable path overrides, operator documentation, and focused plus full-suite coverage.
