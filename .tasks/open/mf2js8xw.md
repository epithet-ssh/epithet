---
yatl_version: 1
title: Coordinate enrollment tokens, host configuration, and inventory federation
id: mf2js8xw
created: 2026-10-24T04:13:35.453651303Z
updated: 2026-11-16T04:45:01Z
author: Brian McCallister
priority: medium
tags:
- design
- control
- inventory
- enrollment
---

# Planning status

Parent plan for four independently scoped work items. The user authorized this
split and an architecture decision record on 2026-11-16. Production implementation
has not started and is not authorized by this documentation update.

[ADR 0003](../../docs/adr/0003-control-issued-enrollment-tokens.md) records the accepted unrestricted-enrollment
decision and reasoning. Child tasks own implementation scope and deferred design;
do not treat the original combined plan as a requirement to implement everything
at once.

## Work split

| Work item | Status and relationship |
| --- | --- |
| [Control-issued unrestricted tokens](f1ljvrhn.md) | Design agreed; implementation not started. First enrollment phase. |
| [Constrained grants and destination identity](7oeid3c2.md) | Deferred design building on unrestricted tokens. |
| [Independent host configuration](ttxxxg3i.md) | Separate work; remaining configuration contracts need design. |
| [Inventory federation](yrwrrbyf.md) | Separate design covering lookup, partial capabilities, and listing. |

Configuration and federation are not prerequisites for unrestricted tokens.
Constrained grants do not block that first phase. No child implies authorization
to implement cloud or hypervisor providers.

## Problem and deployment model

The current enrollment model has two credentials with different lifecycles,
transport, and owners: a control-configured bearer permits pending submissions,
while an inventory-stored single-use token permits activation and becomes the
host ID. This is confusing and couples credentials to resource identity.

Support mixed environments with independent authoritative inventory sources:

- Physical machines can use Epithet-managed inventory and enrollment.
- A service on a hypervisor can supply authoritative inventory for its guest
  VMs. The intended example is one service on the hypervisor, not one per guest.
- AWS or GCP inventory providers can obtain facts from those platforms' APIs.
- External provisioning can invoke host configuration with the CA and realm.
  These machines need not enroll in managed inventory.

These are valid compositions, not a mandatory deployment architecture. Enrollment
is useful where managed registration establishes inventory; it is not required
for every dynamically created machine. Control must remain stateless.

Here, control being stateless means no per-token database or use accounting.
The accepted subject denylist is explicit control configuration, with no extra
history mechanism.

## Decisions and superseded proposals

The first phase uses minimal signed JWTs (`aud`, `exp`, required `sub`), explicit
lifetimes, existing administrative issuance auth, and configured subject denial.
The full contract and tradeoffs live in ADR 0003, not a duplicate specification
in this parent.

- The earlier proposed nested authorization object, custom version/purpose fields,
  and up-front constraint schema are superseded for v1. Constraints are deferred.
- Mandatory control-derived realms are superseded for unrestricted v1. Restricted
  destination identity remains a consequential design problem in the constraints
  task; no derivation algorithm has been selected.
- Signing-key ownership, subject attribution, audience, explicit lifetime, and
  revocation are now settled by the ADR. They are no longer open questions.
- Preserve the current token-creation command/auth flow. The earlier blanket
  statement that existing CLI names need not be preserved no longer applies to
  that command.
- Replace the old credential mechanisms. There is one deployment and no pending
  enrollments; do not add a pending-record migration, recovery, or compatibility
  workflow.

Existing provider boundaries, independent host identity, and atomic creation-only
writes remain foundations. Detailed host configuration and federation discussions
have moved to their respective child tasks without selecting their open contracts.

## Related work

- [s9cqey45](../closed/s9cqey45.md): implemented inventory management/provider
  discovery; retain its history while revisiting enrollment lifecycle and partial
  capabilities in the appropriate children.
- [ywxp1g89](ywxp1g89.md): directory management; directory federation/multiple-IdP
  design remains deferred, with its boundaries retained in the federation task.
- [q06t72c8](q06t72c8.md): ambiguity diagnostics within one inventory provider.

Update service documentation and API contracts when the corresponding behavior is
implemented. ADRs own accepted architecture decisions; YATL owns work status,
acceptance criteria, and remaining design questions.

---
# Log: 2026-10-24T04:13:35Z Brian McCallister

Created task.

---
# Log: 2026-11-16T04:45:01Z Codex

Split into four linked tasks at the user's request. Recorded the agreed minimal
unrestricted-token and subject-denylist decision in ADR 0003. Moved outstanding
configuration, constraint, identity, and federation design into the children;
marked superseded proposals explicitly. No production behavior changed.
