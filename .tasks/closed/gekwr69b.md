---
yatl_version: 1
title: Move OIDC validation and identity normalization into inventory
id: gekwr69b
created: 2026-09-08T00:05:57.457910Z
updated: 2026-09-08T00:59:41.131448Z
author: Brian McCallister
priority: medium
---

Inventory owns OIDC token validation, identity mode and claim mapping, and login discovery. CA passes the opaque token and host to inventory, then normalized authentication and directory/host facts plus connection details to policy. Policy receives no user token and has no OIDC configuration. CA continues enforcing identity, principal, and authentication-expiry bounds before signing.

Move policy.oidc to inventory.oidc, including mode/claim configuration and renamed environment variables. Preserve static directory semantics and the combined epithet server deployment. Dynamic inventory, SCIM, and enrollment remain separate follow-ups.

---
# Log: 2026-09-08T00:05:57Z Brian McCallister

Created task.

---
# Log: 2026-09-08T00:09:32Z Brian McCallister

Started working.

---
# Log: 2026-09-08T00:21:43Z Brian McCallister

Implemented inventory-owned OIDC validation, identity mapping, and discovery. CA coordinates token-to-inventory and normalized-facts-to-policy calls; policy has no OIDC settings or user bearer token. Preserved mode semantics, checked fact binding and expiry, and retained CA certificate bounds. Updated CLI config/env, API docs, deployment samples, and migration guide. make build, explicit go build, make test, targeted race suites, API references, offline examples, and FreeBSD shell syntax checks pass. No FreeBSD runtime deployment performed.

---
# Log: 2026-09-08T00:21:43Z Brian McCallister

Closed.

---
# Log: 2026-09-08T00:59:06Z Brian McCallister

Follow-up requested: rename inventory.files to inventory.static and inventory --files to --static, preserving the list of paths/globs. Updated combined-server forwarding, existing fixtures, docs, and deployment examples.

---
# Log: 2026-09-08T00:59:41Z Brian McCallister

Rename validated: make build, explicit go build, make test, and inventory --check --static all pass. No old option references remain in active code or documentation.
