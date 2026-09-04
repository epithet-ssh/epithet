---
yatl_version: 1
title: Add SCIM provisioning and persistent group-name bindings
id: 8jwaf0d8
created: 2026-09-05T16:50:06.836671Z
updated: 2026-09-05T16:54:13.275546Z
author: Brian McCallister
priority: high
tags:
- inventory
- scim
- security
blocked_by:
- 512htw8r
---

Later phase after initial dynamic inventory, not day-one scope for a5qt7g3m or 512htw8r. Expose SCIM provisioning for managed users and groups through inventory. Preserve canonical SCIM documents and extension attributes; keep the authorization projection small and the persistence details inside inventory. Use the SCIM User and enterprise User extension representation already adopted for resolver responses.

Managed group names require durable bindings to immutable group IDs:
- On first unambiguous policy application, bind the readable group reference (for example group:SRE) to one immutable SCIM group ID.
- Later duplicate display names warn without broadening membership or invalidating the established binding.
- Deletion leaves a tombstone. A newly created group with the same display name is never silently adopted.
- Initial ambiguity requires explicit administrative selection; provide an audited way to manage/rebind the resulting state.
- Avoid both privilege broadening and a global denial of service when duplicate names appear.

Static inventory remains simpler: userName and group names are the IDs; no separate ID fields or managed binding lifecycle are required in its YAML. Do not burden static inventory with synthetic-ID configuration for future SCIM support.

Update Writ SPEC and evaluation/binding integration together: the existing duplicate-display-name union-with-warning text is superseded for managed inventory. Pre-1.0 compatibility must not preserve the unsafe managed behavior. Define binding ownership and how bindings participate in coherent evaluation revisions without introducing policy-to-inventory calls: all core service calls must still originate at CA.

Keep SCIM provisioning authentication separate from resolution reads, enrollment admission, and human administration. Shared OIDC authentication does not replace inventory RBAC. Define write/retry/uniqueness and document-plus-projection atomicity before implementation; IdP provisioning populates inventory asynchronously rather than becoming a live dependency of certificate issuance.

Acceptance: memberships are evaluated against the selected group IDs; duplicates, deletions, same-name replacements, and explicit rebindings have tested behavior; additional SCIM attributes survive storage round trips; static literal-name behavior remains straightforward. A specific SCIM library and exact provisioning API/configuration are still to be selected.

---
# Log: 2026-09-05T16:50:06Z Brian McCallister

Created task.

---
# Log: 2026-09-05T16:54:13Z Brian McCallister

Added blocker: 512htw8r
