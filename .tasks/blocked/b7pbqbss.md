---
yatl_version: 1
title: Enforce client trust in enrolled host keys
id: b7pbqbss
created: 2026-09-03T03:26:05.067815Z
updated: 2026-09-03T03:26:10.291447Z
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
