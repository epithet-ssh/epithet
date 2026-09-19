---
yatl_version: 1
title: Revisit whether managed host inventory should require opt-in
id: 2krqtk0f
created: 2026-09-17T23:02:40.091214Z
updated: 2026-09-19T00:25:51.036303Z
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

---
# Log: 2026-09-19T00:24:07Z Brian McCallister

User explicitly selected managed host inventory as the default during deployment follow-up. Managed mode composes static records with enrolled hosts; inventory-source: static remains the opt-out. This removes the extra activation setting encountered during the SCIM upgrade. Startup and inventory --check consequently require usable managed host storage, and existing state-dir paths must use the shared root.

---
# Log: 2026-09-19T00:25:51Z Brian McCallister

Closed: Selected and implemented managed host inventory by default, preserving explicit static opt-out. Also made epithet-principal-v1 the inventory service default at the user request. Updated help, examples, migration guidance, and tests; full suite and combined-server default enrollment validation pass.
