---
yatl_version: 1
title: Implement file-backed dynamic host enrollment and inventory administration
id: zf00zcgj
created: 2026-09-12T03:51:04.487471Z
updated: 2026-09-12T04:17:02.441523Z
author: Brian McCallister
priority: high
tags:
- inventory
- host-enrollment
---

---
# Log: 2026-09-12T03:51:04Z Brian McCallister

Created task.

---
# Log: 2026-09-12T03:53:28Z Brian McCallister

Started working.

---
# Log: 2026-09-12T04:15:46Z Brian McCallister

Implemented managed host enrollment and inventory-admin operations with a single locked, atomically replaced YAML snapshot. Reuses directory identity mapping and the agent login; CA advertises managed endpoint. Includes source precedence, pending review, removal tombstones, single-use tokens, and end-to-end issuance coverage. Operator summary: docs/dynamic-inventory.md.

---
# Log: 2026-09-12T04:17:02Z Brian McCallister

Validation passed: make build (plus explicit go build ./cmd/epithet because the Makefile target was already present), make test, go test -race ./pkg/broker ./pkg/inventory ./pkg/inventoryserver, and a FreeBSD amd64 cross-build. The combined-server integration test exercises real admin CLI operations through the broker and checks issuance before approval, after approval, and after removal. No deployment or real sshd changes were performed.

---
# Log: 2026-09-12T04:17:02Z Brian McCallister

Closed.
