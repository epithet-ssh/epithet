---
yatl_version: 1
title: Evolve Writ selectors and provider-defined facts
id: rv3znarg
created: 2026-10-12T09:15:55.707178Z
updated: 2026-10-12T10:16:14.917584Z
author: Brian McCallister
priority: medium
tags:
- writ
- design
- facts
---

Track the work to realize ADR 0001, docs/adr/0001-writ-object-selectors-and-provider-facts.md. The ADR owns the durable technical decision, alternatives, rationale, and consequences; this task owns open design work, sequencing, and the eventual implementation plan.

The agreed direction is structured object filters using colons and AND on the same object, repeated rules for OR, provider-defined attributes, multi-valued name as the fixed default selector attribute, and explicit identity selection. Trust current provider names rather than preserving historical group-name bindings.

## Current scope

Complete the remaining semantic decisions before preparing an implementation plan. Application implementation is not yet authorized. Record newly agreed technical decisions and their reasoning in the ADR, rather than copying task status or execution steps into it.

## Open design work

1. **Fact shape and identity.** Specify object and membership envelopes, required
   fields, group ID provenance and scope, and what providers without group IDs
   can express. Separate operational data from selectable attributes. Multiple
   user names also require deciding which name, if any, is used for certificate
   key IDs and audit presentation; an array's first element is not yet a contract.
2. **Values and paths.** Define supported scalar types, collections beyond `name`,
   equality and coercion, normalization, quoting, and duplicate predicate keys.
   Decide whether nested paths are needed and
   how escaping and arrays work. No general JSON query language is selected.
3. **Absence and failure.** Define missing attributes, nulls, empty collections,
   and type mismatches, including their interaction with deny negation. A valid
   unfamiliar attribute and a failed or invalid fact response are different
   cases. Do not accidentally turn a provider failure into a successful negation.
4. **Composition and transition.** Specify macros and deny negation under the
   no-inline-OR decision, including existing user, host, and account unions.
   Preserve explicit rule precedence and clause behavior when alternatives
   become separate rules. Account for compiled policy producers and content IDs.


## Sequence and dependencies

Resolve the semantic questions above, then prepare the implementation plan for discussion. The plan must account for the specification, source and compiled IL, fact adapters, direct IL producers, and callers. Do not silently choose unresolved semantics as implementation details.

Land the Writ evolution before finalizing the fact-service management contract tracked in s9cqey45. Reassess directory binding and reconciliation operations under the new semantics, including the older management work in 1c682zm5. Principal realms are a certificate mechanism, not a Writ policy design question.

## Completion

The agreed semantics are recorded, the separately agreed implementation is complete and validated, and the specification and consumers describe the same behavior. Until then this task remains open; drafting ADR 0001 alone does not complete this feature.

---
# Log: 2026-10-12T09:15:55Z Brian McCallister

Created task.

---
# Log: 2026-10-12T10:12:45Z Brian McCallister

Clarified host filter syntax in ADR 0001: root@{environment:production} is the attribute-only form; a hostname prefix adds an implicit name predicate, so root@web01{environment:production} is a conjunction. No host kind marker after @ and no redundant root@*{...} spelling.

---
# Log: 2026-10-12T10:16:14Z Brian McCallister

Confirmed empty filters are valid and accept any candidate object. ADR 0001 records root@{} as equivalent to root@*, with normal resolution and eligibility constraints intact. Removed empty-filter validity from open design questions.
