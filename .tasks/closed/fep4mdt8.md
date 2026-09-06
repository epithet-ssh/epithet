---
yatl_version: 1
title: Map OIDC claims to static inventory IDs
id: fep4mdt8
created: 2026-09-07T03:29:36.116873Z
updated: 2026-09-07T03:42:27.929854Z
author: Brian McCallister
priority: high
tags:
- identity
- inventory
---

Normalize a verified OIDC claim to the provider-scoped static inventory id. Add policy.oidc.user-id-claim with provider defaults (sub for Google/Okta/generic OIDC; oid for tenant-specific Microsoft Entra). Static YAML requires id and rejects subject/oidc-subject; Writ matches the normalized ID while names and other attributes stay in inventory. Move the identity helper to epithet agent identity, using the running agent authentication cache and advertised policy mapping, returning verified identifiers without credentials or requesting a certificate. No SCIM layer or inventory/directory terminology refactor in this task.

---
# Log: 2026-09-07T03:29:36Z Brian McCallister

Created task.

---
# Log: 2026-09-07T03:29:49Z Brian McCallister

Started working.

---
# Log: 2026-09-07T03:41:05Z Brian McCallister

Implemented provider-scoped static id lookup and Writ IDs, configurable policy.oidc.user-id-claim with Entra oid and generic sub defaults, strict selected-claim validation, and discovery of the effective mapping. Moved identity to epithet agent identity; it uses the live agent profile, shared authentication cache, verified token mapping, streamed login progress, and JSON identifiers without requesting certificates. Legacy subject keys and standalone identity command are rejected. Updated examples, migration guidance, architecture, and security regression coverage. make build and explicit go build passed; full make test and go test -race ./pkg/broker passed with local socket access; final Writ integration tests and CLI example/help checks passed. Provider-specific token fixtures are local, not live-provider integrations. Deferred host inventory versus user directory naming as discussed.

---
# Log: 2026-09-07T03:41:05Z Brian McCallister

Closed.

---
# Log: 2026-09-07T03:42:27Z Brian McCallister

Final review: cache the agent identity verifier and signing keys after successful lazy discovery; retry failed discovery on later requests. Concurrent agent identity verifier tests passed under the race detector, and the final binary rebuilt successfully.
