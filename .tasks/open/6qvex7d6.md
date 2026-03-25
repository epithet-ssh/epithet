---
yatl_version: 1
title: ADR infrastructure and draft ADRs (CA/policy separation + token validator plugin)
id: 6qvex7d6
created: 2026-03-24T17:32:59.386215086Z
updated: 2026-03-25T04:11:04.815338870Z
author: Brian McCallister
priority: high
tags:
- architecture
- docs
---

Write ADR infrastructure (docs/adr/ with README template) and two draft ADRs: 0001 covering CA/policy server separation (keep separate, Sigstore consistent across modes, policy server is a reference implementation) and 0002 covering token validator plugin mechanism (gRPC over Unix socket via EPITHET_PLUGIN_SOCKET env var). Draft ADRs are written; they need review before being marked accepted.

---
# Log: 2026-03-24T17:32:59Z Brian McCallister

Created task.
