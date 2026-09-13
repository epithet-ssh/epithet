---
yatl_version: 1
title: Simplify enrollment to the agreed editor and token workflow
id: 7nneqak9
created: 2026-09-13T03:35:01.386226Z
updated: 2026-09-13T03:47:56.745978Z
author: Brian McCallister
priority: high
tags:
- inventory
- enrollment
---

---
# Log: 2026-09-13T03:35:01Z Brian McCallister

Created task.

---
# Log: 2026-09-13T03:36:56Z Brian McCallister

Started working.

---
# Log: 2026-09-13T03:47:56Z Brian McCallister

Restored editor-only enrollment with parse/validation re-editing and single-use tokens. Removed proposal-file/yes flags, persistent enrollment credentials, API/storage retry fields and indexes, and all compatibility reads for credential files. Hostname proposals read the local hostname and configured search-domain suffix without DNS lookup. Added a typed inventory RPC client and moved operations out of caclient. Replaced the CA setter with PublicInventoryURL, allowed public endpoint queries with explicit validation errors, clarified static override versus degraded startup, and simplified router cleanup. Ran go fmt; make build and explicit native/FreeBSD builds passed; make test and broker/inventory/client/command race tests passed.

---
# Log: 2026-09-13T03:47:56Z Brian McCallister

Closed: Completed the requested review corrections and removed the unrequested enrollment mechanisms.
