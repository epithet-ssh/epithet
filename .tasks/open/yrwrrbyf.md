---
yatl_version: 1
title: "Design inventory federation, partial capabilities, and listing"
id: yrwrrbyf
created: 2026-11-16T04:45:01Z
updated: 2026-11-16T04:45:01Z
author: Codex
priority: medium
tags:
- design
- inventory
- control
---

Parent: [mf2js8xw](mf2js8xw.md).

# Status and independence

Separate design work. Implementation and cloud/hypervisor adapters are not
authorized by this planning update. This is not a prerequisite for
[control-issued enrollment tokens](f1ljvrhn.md); see
[ADR 0003](../../docs/adr/0003-control-issued-enrollment-tokens.md).

## Lookup direction

- Support multiple inventory providers. A host SHOULD be served by exactly one
  provider, with no overlapping name claims across providers.
- Query providers concurrently and accept the first valid complete host
  response. A provider outage must not prevent another provider resolving a
  host. Resolution does not need to prove global uniqueness on every request.
- Do not merge facts, aliases, accounts, labels, principal mode, or realm from
  multiple providers. Missing fields are not filled from another response.
- Treat overlapping claims as an ownership/configuration error. Detecting
  collisions is useful but is not a lookup prerequisite or a blocker on a
  healthy provider's answer. With broken uniqueness, response timing can select
  different authoritative records; this is an accepted consequence of the
  availability direction, not an endorsement of overlapping ownership.
- No mandatory disjoint-namespace routing or coordinated global registration.
  A configured predicate to skip irrelevant providers is a possible later
  optimization only if needed.
- Provider selection for management is a separate question from federated reads;
  lookup federation does not imply broadcasting writes or merging management
  results.

## Partial capabilities

- A provider may support lookup and listing without supporting enrollment or
  other mutations. Cloud-backed inventory is a concrete example.
- Build on existing capability advertising instead of inventing it anew:
  public control already advertises capabilities; inventory providers already
  advertise resource templates with signed OPTIONS and Link-Template.
- Current discovery requires the complete records/tokens/audit relation set and
  infers `enroll` from its presence. The current contracts do not cleanly express
  a listing-only provider. Extend the granularity and relax the all-or-nothing
  assumption; the precise advertisement contract remains open.

## Open contracts

- Placement in the existing fact client versus a separate federating service;
  endpoint configuration, provider identity, and authentication/key configuration.
  Direct client composition was suggested but not selected.
- Cancellation, bounded lookup lifetime, and the no-success result when some
  providers fail versus all reporting absence. Any collision diagnostics must
  preserve the agreed availability behavior.
- Supported operations separately from resource locations, using existing
  discovery. Decide provider-scoped versus aggregate public capabilities and how
  the CLI chooses an enrollment or management target.
- Federated listing: aggregation, provider-local IDs/cursors, pagination,
  unavailable/non-listing providers, and representation of incomplete coverage.

## Completion criteria for design

Specify lookup outcomes, placement/configuration, capability discovery, write
routing, and listing semantics. Compare materially different placements for their
caller and implementation complexity. Preserve complete authoritative records and
the accepted availability tradeoff; do not add global uniqueness coordination or
mandatory namespace routing.

## Related work and boundaries

[q06t72c8](q06t72c8.md) covers ambiguity within a provider, which is distinct from
cross-provider availability. Existing discovery lives in
`pkg/facts/control/server.go` and `pkg/facts/control/inventory.go`.

Directory federation and multiple-IdP support are deferred separately. Multiple
IdPs do not necessarily imply multiple directories. A future directory design
must address issuer-scoped identity, deliberate account linking, group identity,
and authority ownership. Existing directory management is tracked in
[ywxp1g89](ywxp1g89.md); no directory federation contract has been selected.

---
# Log: 2026-11-16T04:45:01Z Codex

Created from mf2js8xw at the user's request; planning only.
