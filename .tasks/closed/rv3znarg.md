---
yatl_version: 1
title: Evolve Writ selectors and provider-defined facts
id: rv3znarg
created: 2026-10-12T09:15:55.707178Z
updated: 2026-10-12T14:40:17.210112Z
author: Brian McCallister
priority: medium
tags:
- writ
- design
- facts
---

Implement ADR 0001, docs/adr/0001-writ-object-selectors-and-provider-facts.md.
The ADR owns the technical decisions; this task tracks their implementation.

## Completed scope

- Single object selectors with string predicates and same-object AND, repeated
  keys, multivalued facts, flat attributes, name shorthand, and empty filters.
  Alternatives use separate rules. Macros alias one positive same-kind selector;
  negation remains confined to whole selectors in deny heads.
- IL schema 3 with selector-position validation and new canonical rule IDs.
  Older schemas and retired syntax are rejected without compatibility shims.
- Shared explicit name/id fields and additional string attributes. User IDs bind
  authentication, userName remains presentation, and providers own eligibility.
  Group memberships remain separate objects with optional IDs. Host account
  filters retain null/unrestricted, empty/none, and list/restricted behavior.
- SCIM memberships expose current display names, resource IDs, and optional
  externalId. Removed historical group bindings, bind CLI/API, and alias storage.
  Group listing shows current names and IDs; admin grants follow current names.
  Audit history remains inspectable.
- Direct creation of SQLite schema version 2 and rejection of unsupported
  versions, with initialization/reopen/version-check tests. Existing deployments
  use disposable external conversion tools. A migration framework remains
  deferred in gt3vjk35.
- Updated specification, provider API schemas, source fixtures, editor syntax,
  and directory mapping/upgrade documentation.

## Validation

Passed make -B build and make test. Coverage includes same-group conjunction,
repeated keys, missing/empty values, malformed fact rejection, host alias denials,
account filters, SCIM name reuse/rename and resource-ID selection, administration,
and full SSH integration tests.

LDAP/EC2 implementations and provider management discovery remain out of scope.
The latter is still a design task in s9cqey45. Historical binding-management work
remaining in 1c682zm5 is superseded; its completed user listing is retained.

---
# Log: 2026-10-12T09:15:55Z Brian McCallister

Created task.

---
# Log: 2026-10-12T10:12:45Z Brian McCallister

Clarified host filter syntax in ADR 0001: root@{environment:production} is the attribute-only form; a hostname prefix adds an implicit name predicate, so root@web01{environment:production} is a conjunction. No host kind marker after @ and no redundant root@*{...} spelling.

---
# Log: 2026-10-12T10:16:14Z Brian McCallister

Confirmed empty filters are valid and accept any candidate object. ADR 0001 records root@{} as equivalent to root@*, with normal resolution and eligibility constraints intact. Removed empty-filter validity from open design questions.

---
# Log: 2026-10-12T10:58:12Z Brian McCallister

Implementation requested. Agreed that SCIM group externalId maps to the internal policy id attribute; recorded the mapping and rationale in ADR 0001. Missing group IDs and lifecycle enforcement remain open.

---
# Log: 2026-10-12T11:06:46Z Brian McCallister

Supersedes the earlier externalId mapping: expose the SCIM group resource id as the id attribute in returned group facts. externalId may be exposed separately and remains optional. Group IDs are not required in the general fact model; static groups need no manufactured IDs. Users still require canonical authentication IDs. Recorded in ADR 0001.

---
# Log: 2026-10-12T11:09:02Z Brian McCallister

Agreed to retain explicit userName for certificate key IDs, falling back to canonical user ID. Audit identity remains canonical user ID. Selectable name collection order has no presentation meaning. Recorded in ADR 0001; removed this open design question.

---
# Log: 2026-10-12T11:14:05Z Brian McCallister

Agreed string-only selector values and equality. A predicate selects one string; any matching value of a multivalued fact attribute satisfies it. No Writ array literals or array comparisons, numeric or boolean predicate types, or implicit conversion to them. Numeric matching is deferred until a concrete user request. Existing hostname-pattern behavior remains. Recorded in ADR 0001.

---
# Log: 2026-10-12T11:15:48Z Brian McCallister

Confirmed missing attributes do not match and negation stays confined to whole user, account, or host selectors in deny heads. Allow rules and macro bodies remain positive. Provider failures and malformed fact responses remain errors that prevent authorization. Recorded in ADR 0001.

---
# Log: 2026-10-12T11:17:07Z Brian McCallister

Agreed flat selectable attributes. Predicate keys select attributes directly; providers map source data into that flat model. No nested traversal or path syntax. Recorded in ADR 0001 and removed nested paths from open design work.

---
# Log: 2026-10-12T11:19:02Z Brian McCallister

Agreed macros alias one positive selector or another macro of the same declared kind. References add or combine no predicates and introduce no alternatives or negation. Retain existing define-before-use and kind checks. Recorded the admins/deployers example in ADR 0001.

---
# Log: 2026-10-12T11:19:55Z Brian McCallister

Agreed repeated attribute keys preserve conjunction: group{role:admin, role:oncall} requires one group with both values. Predicates do not overwrite each other, and identical repeated predicates do not change the match. Recorded in ADR 0001.

---
# Log: 2026-10-12T11:26:33Z Brian McCallister

Agreed selectable attribute value handling: missing, null, and empty collections supply no values; an empty string is a value matching an explicitly empty predicate. Numbers, booleans, objects, and collections containing non-strings invalidate the fact response. Operational fields remain separately validated. Recorded in ADR 0001.

---
# Log: 2026-10-12T12:25:56Z Brian McCallister

Confirmed the fact model after SCIM, LDAP, and EC2 thought exercises: explicit name/id fields, flat additional attributes, structured groups, provider-owned eligibility with no active in authorization facts, and unchanged accounts null/list/empty semantics. Recorded in ADR 0001. Prepared implementation plan; remaining operational consequence is retirement of historical group-binding administration and its storage.

---
# Log: 2026-10-12T12:47:25Z Brian McCallister

Started working.

---
# Log: 2026-10-12T12:47:25Z Brian McCallister

Approved retirement of historical group bindings, including bind CLI, current-name/SCIM-ID group listing, retained audit inspection, and current group names for administrator grants. Beginning implementation.

---
# Log: 2026-10-12T13:16:07Z Brian McCallister

Closed: Implemented ADR 0001 and the transactional directory schema upgrade; make -B build and make test pass.

---
# Log: 2026-10-12T14:40:17Z Brian McCallister

Revised database handling after review: create version 2 directly, reject other versions without upgrading, and remove migration-specific tests. One-off conversion tooling stays outside the repository; the migration-framework task gt3vjk35 is reopened.
