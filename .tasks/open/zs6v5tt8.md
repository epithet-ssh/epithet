---
yatl_version: 1
title: Bind issued SSH certificate principals to registered host accounts
id: zs6v5tt8
created: 2026-08-23T14:53:16.777722Z
updated: 2026-08-23T14:53:31.552048Z
author: Brian McCallister
priority: critical
tags:
- writ
- security
---

Implement destination-bound SSH certificate issuance using opaque, unguessable principals registered per host account.

The host registration/configuration API must authenticate hosts and maintain a mapping from (host, account) to an opaque UUID principal. The policy server must return that principal after authorizing account@host, and the target host must list it in the account's AuthorizedPrincipalsFile (or equivalent command). Principal values must be unique across hosts/accounts and rotation/removal semantics must fail closed.

Threat-model and design the registration surface before implementation: bootstrap identity, authorization to create/replace mappings, replay/rollback resistance, atomic inventory replacement, staleness, deletion, UUID generation ownership, auditability, and recovery. Add an end-to-end regression proving a certificate authorized for account@host A is rejected for the same account on host B.

Until this task is complete, documentation and the Writ specification must describe host selectors as issuance-time conditions within a shared CA trust domain, not destination enforcement.

---
# Log: 2026-08-23T14:53:16Z Brian McCallister

Created task.
