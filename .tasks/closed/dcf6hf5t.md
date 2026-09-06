---
yatl_version: 1
title: Honor existing client configuration in identity command
id: dcf6hf5t
created: 2026-09-06T03:42:17.288993Z
updated: 2026-09-06T03:45:23.706789Z
author: Brian McCallister
priority: medium
tags:
- cli
- config
---

The identity command now inherits agent.ca-url from the existing client configuration when neither an identity-specific CA setting nor a CLI override is supplied. Precedence: --ca-url > identity.ca-url > agent.ca-url. Reuses the Kong YAML loader for inherited values to preserve scalar/list support, multiple default files, explicit --config overlays, priorities, and CA failover. Global TLS flags/config remain unchanged. No server-side policy.oidc fallback was introduced; the user confirmed this is a client command. Documented the deliberate cross-command fallback. Ten configuration cases pass, the built CLI smoke test confirmed --config inheritance before network access, make build plus explicit go build succeeded, and make test passed.

---
# Log: 2026-09-06T03:42:17Z Brian McCallister

Created task.

---
# Log: 2026-09-06T03:43:57Z Brian McCallister

Started working.

---
# Log: 2026-09-06T03:45:23Z Brian McCallister

Implemented and validated client-side configuration fallback with explicit precedence; user confirmed the cross-command exception is intentional.

---
# Log: 2026-09-06T03:45:23Z Brian McCallister

Closed.
