---
yatl_version: 1
title: Revisit whether managed host inventory should require opt-in
id: 2krqtk0f
created: 2026-09-17T23:02:40.091214Z
updated: 2026-09-17T23:03:37.945901Z
author: Brian McCallister
priority: medium
tags:
- inventory
- configuration
- design
---

Revisit whether managed host inventory should be the default instead of requiring explicit opt-in. The user suspects the current opt-in decision may be wrong and requested a separate follow-up during review of SCIM integration (8jwaf0d8).

The current change separates selection from storage: inventory-source defaults to static, inventory-source: managed enables enrolled hosts in addition to static hosts, and state-dir has a native system storage default. Treat the opt-in choice as provisional rather than an established product requirement.

Compare managed-by-default with explicit opt-in using actual operator setup and deployment experience. Consider whether an explicit static-only mode remains useful, startup/storage requirements, enrollment availability, and migration from existing configurations. Discuss and settle the desired behavior before implementation; no change to the default is authorized by this task alone.

Acceptance: record the decision and rationale, implement any agreed default/configuration migration, update examples and help, and verify standalone and combined service behavior. Coordinate with 8rywbj6z if separating administration affects configuration, but do not conflate the two decisions.

---
# Log: 2026-09-17T23:02:40Z Brian McCallister

Created task.
