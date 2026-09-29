---
yatl_version: 1
title: Enforce client trust in enrolled host keys
id: b7pbqbss
created: 2026-09-03T03:26:05.067815Z
updated: 2026-09-29T02:18:09.804821Z
author: Brian McCallister
priority: critical
tags:
- epithet-enterprise
- ssh
- security
blocked_by:
- 508fj5h3
---

Publish enrolled host keys in known_hosts form and integrate an authenticated local cache with OpenSSH KnownHostsCommand and StrictHostKeyChecking=yes. Acceptance: aliases bind to the registered identity; lookups avoid repeated network calls; missing, conflicting, stale, or mismatched keys fail closed; a newly enrolled ephemeral host becomes connectable without manually editing known_hosts; SSH host certificates remain a documented future-compatible path rather than a first-version requirement.

---
# Log: 2026-09-03T03:26:05Z Brian McCallister

Created task.

---
# Log: 2026-09-29T02:18:09Z Brian McCallister

Closed: Superseded / alternate chosen, per user decision. Retire the historical inventory-owned host-control chain in favor of the implemented enrollment and separate control-service approach. This closure records a design decision, not completion of every original acceptance criterion; deferred features in this chain are not carried forward as requirements.
