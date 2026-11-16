---
yatl_version: 1
title: "Design constrained enrollment grants and destination identity"
id: 7oeid3c2
created: 2026-11-16T04:45:01Z
updated: 2026-11-16T04:45:01Z
author: Codex
priority: medium
tags:
- design
- control
- enrollment
---

Parent: [mf2js8xw](mf2js8xw.md).

# Status and dependency

Deferred design. Builds on [unrestricted enrollment tokens](f1ljvrhn.md)
and [ADR 0003](../../docs/adr/0003-control-issued-enrollment-tokens.md); it is not a prerequisite for v1.
Implementation and a future claim format are not authorized by this planning update.

## Intended direction

Restrict enrollment to permitted host facts through patterns rather than a set of
special-case suffix options or a mutable stored template. Earlier illustrative
issuing options were `--name '*.workers.example.com' --account '*'`; these are not
a finalized CLI or schema. The fixed-label-template proposal was not selected.
Control should validate any signed constraints before an authorized inventory
write. Retain reusable credentials, independent host IDs, and creation-only writes.

Existing unrestricted tokens retain their meaning until expiry or subject
revocation. Design how a verifier rejects constraints it cannot enforce when the
constrained format is chosen. Do not add placeholder fields or variants to v1.

## Destination identity requiring resolution

The following reasoning from the parent applies to restricted grants. Mandatory
control-derived realms were superseded for unrestricted v1; deterministic realm
derivation remains a working direction here, not a settled solution.

- Names, labels, and accounts are policy facts. Realm and principal mode also
  determine the certificate identity and require explicit control.
- Do not allow an enrolling machine to choose an arbitrary realm, even if the
  realm appears to be generated. Otherwise an attacker with worker enrollment
  authority and worker SSH access could register worker facts using a production
  realm, obtain a certificate under worker policy, and reuse that principal
  against production for the same account.
- The working direction is for control to determine principal mode and derive
  the per-host realm deterministically from the stable host identity. Inventory
  persists the complete record rather than owning Epithet realm-generation
  policy. Determinism removes random-assignment coordination across retries and
  stateless control instances. The exact derivation is still open.
- An intentionally shared realm is a separate, explicit authorization choice
  by the issuer. A shared realm makes certificates usable across that realm for
  the same account. The discussed grant shape uses a per-host identity rule or
  an exact authorized shared realm, not an arbitrary host-selected realm glob.

A derivation from a host-chosen ID alone does not establish isolation. Resolve
identity scope across providers/deployments and deletion/recreation or ID reuse.
Knowing a realm or ID must never authorize replacement. Restricted fact authority
must not let its holder reproduce a more privileged destination's identity.

## Open contracts

- Which fields support patterns, reuse of existing matchers, repeated-pattern
  behavior, normalization, and required versus omitted constraints.
- Missing/extra label keys and every representation of accounts, including the
  difference between omitted/unrestricted accounts and an empty account list.
- Explicitly authorized principal modes, per-host identity rules, and intentionally
  shared realms. Settle encoding/domain separation if deterministic derivation is
  chosen.
- Signed representation and enforcement of constraints, incremental introduction
  of restrictions, and rejection by verifiers that cannot enforce them. No nested
  `authorization.kind` design or custom version field is preselected.

## Completion criteria for design

Produce a concrete grant contract and allowed/rejected submission examples,
including omission and normalization cases. Explain destination isolation and
creation-only behavior, preserve the meaning of existing unrestricted tokens,
and record agreed decisions before turning them into implementation work.

---
# Log: 2026-11-16T04:45:01Z Codex

Created from mf2js8xw at the user's request; planning only.
