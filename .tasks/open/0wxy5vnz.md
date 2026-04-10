---
yatl_version: 1
title: Remove direct CUE dependency
id: 0wxy5vnz
created: 2026-04-10T14:32:25.298636Z
updated: 2026-04-10T14:32:36.719529Z
author: Brian McCallister
priority: medium
---

Goal: remove the runtime dependency on CUE for config loading while preserving the ability for advanced users to author configs in CUE and export to YAML/JSON. Update loaders and CLI wiring to consume plain YAML/JSON only, and ensure policy server validation still covers schemas. Consider whether to document the optional CUE workflow or leave it undocumented if it adds noise.

---
# Log: 2026-04-10T14:32:25Z Brian McCallister

Created task.
