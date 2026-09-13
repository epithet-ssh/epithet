---
yatl_version: 1
title: Move combined-server routing out of the CA into a proxy
id: 2jppyjx4
created: 2026-09-13T02:50:01.330424Z
updated: 2026-09-13T02:56:56.043383Z
author: Brian McCallister
priority: high
tags:
- server
- inventory
---

---
# Log: 2026-09-13T02:50:01Z Brian McCallister

Created task.

---
# Log: 2026-09-13T02:51:34Z Brian McCallister

Started working.

---
# Log: 2026-09-13T02:56:55Z Brian McCallister

Added a dedicated plain-HTTP router subprocess; moved CA to a private Unix socket beside inventory and policy. Removed CA proxy mode, retained relative inventory discovery, and kept service authentication in each backend. Documented Caddy TLS/ACME topology. Passed make build, explicit native build, make test, command/router and broker race tests, FreeBSD amd64 cross-build, and uncached server integration covering external TLS, enrollment/admin/issuance, socket topology, shutdown, and router bind-failure cleanup.

---
# Log: 2026-09-13T02:56:56Z Brian McCallister

Closed: Implemented and validated the separate router and consistent private service topology.
