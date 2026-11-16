---
yatl_version: 1
title: "Separate host configuration from managed enrollment"
id: ttxxxg3i
created: 2026-11-16T04:45:01Z
updated: 2026-11-16T04:45:01Z
author: Codex
priority: medium
tags:
- design
- host
- enrollment
---

Parent: [mf2js8xw](mf2js8xw.md).

# Status and independence

Separate work with open design details; implementation not started or authorized
by this planning update. This is not a prerequisite for
[control-issued enrollment tokens](f1ljvrhn.md). See
[ADR 0003](../../docs/adr/0003-control-issued-enrollment-tokens.md) for the enrollment boundary.

## Agreed direction

- Introduce `epithet host configure` to install local CA trust and SSH principal
  configuration using supplied facts, without enrolling or creating inventory.
- Factor `host enroll` to share that configuration implementation. Enrollment
  establishes a managed record and combines registration with local setup.
- The minimum local contract is CA trust, principal mode, and the exact realm
  for destination-bound principals. Names, labels, and permitted accounts are
  authoritative inventory facts, not necessarily inputs needed by configure.
- The illustrative provisioning command was
  `epithet host configure --ca ... --realm ...`. Exact CLI spelling and input
  requirements are not settled; the current enrollment flag is
  `--principal-realm`.
- Provisioning and the inventory provider must agree on the installed principal
  mode and realm. VM identity should be based on a durable infrastructure
  identity, not the current hypervisor address.

## Open contracts

Settle final input/CLI names, explicit principal facts, bootstrap CA trust via
`--ca`, and the shared internal interface. Specify registration/configuration
ordering, rerun behavior, and failure semantics. Fully offline CA-key input was
raised but neither decided nor requested. Existing workflow is not a compatibility
requirement to preserve automatically.

## Completion criteria

Define the local configuration contract before implementation. Configuration must
install supplied trust/principal settings without registration or inventory
writes; managed enrollment should share that implementation. Validate the agreed
rerun/failure behavior and agreement between installed principal identity and
inventory facts.

## Current code

`cmd/epithet/host_enroll*.go` currently combines local setup and registration.
External provisioning or a hypervisor/cloud inventory source can supply facts
without managed enrollment; no new provider adapters are implied by this task.

---
# Log: 2026-11-16T04:45:01Z Codex

Created from mf2js8xw at the user's request; planning only.
