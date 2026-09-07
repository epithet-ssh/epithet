---
yatl_version: 1
title: Remove SCIM protocol scaffolding from internal inventory user facts
id: hmh7yb8s
created: 2026-09-08T02:35:09.321602Z
updated: 2026-09-08T02:35:09.325118Z
author: Brian McCallister
priority: high
tags:
- api
- architecture
---

Source: API audit thbfp6pt (.tasks/closed/thbfp6pt.md). User requested high-priority remediation tasks; filing does not implement the proposed changes.

Problem: the internal user response carries SCIM schemas URNs, an enterprise-extension URI property, and group objects whose value and display are identical. Policy uses only group value. Our internal protocol does not need to implement SCIM's wire format.

Replace the internal shape with ordinary id, userName, active, groups, userType, department, and organization fields. Remove schemas and its validation; flatten the enterprise attributes; represent group membership with strings. Future SCIM adapters translate external records at their boundary.

Acceptance:
- Preserve byte-exact id/userName/group matching, activity checks, enterprise-attribute policy semantics, and absent-user denial.
- No schema URI or redundant group display value remains in the internal request/response contract.
- Update resolver, policy consumers, API docs/examples, and meaningful authorization regression fixtures.
- Do not alter static YAML or implement SCIM provisioning as part of this cleanup.

---
# Log: 2026-09-08T02:35:09Z Brian McCallister

Created task.
