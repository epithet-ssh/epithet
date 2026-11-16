---
yatl_version: 1
title: "Implement control-issued unrestricted enrollment tokens"
id: f1ljvrhn
created: 2026-11-16T04:45:01Z
updated: 2026-11-16T04:45:01Z
author: Codex
priority: medium
tags:
- control
- inventory
- enrollment
---

Parent: [mf2js8xw](mf2js8xw.md).

# Status and decision

Design agreed; implementation not started. This task split and ADR are planning
changes, not authorization to implement production code.

[ADR 0003](../../docs/adr/0003-control-issued-enrollment-tokens.md) is the authoritative decision and rationale.
Implement its minimal `aud`, `exp`, `sub` contract and configured subject denylist.
Do not reintroduce the earlier nested authorization or mandatory control-derived
realm proposals into this phase.

## Implementation scope

- Preserve `epithet inventory token create` and its existing administrative auth
  flow. Require `--subject` and explicit positive `--expires-in`; remove the 24h
  cap. Control signs with its existing key instead of delegating issuance to
  inventory.
- Verify the configured signing key, enrollment audience, expiry, required
  nonempty subject, and configured subject denylist. Denied subjects cannot be
  issued new tokens or enroll hosts. Match subjects exactly and case-sensitively.
- Wire the denylist through normal control configuration/startup. It only grows
  operationally; no history store, hot reload, individual token tracking, or
  issued-at cutoff is part of this work.
- Keep host IDs independent and stable across retries. Pass authorized
  creation-only writes to inventory without the public credential, and preserve
  atomic create/identical-retry/conflict behavior. New records are active.
- Attribute enrollment audit events to the verified subject. Preserve unchanged
  retries without duplicate mutation audit events.
- Replace the old pending-enrollment bearer and single-use credential machinery,
  including manual enrollment approval and per-token revocation flows. Keep
  existing active hosts. The single deployment has no pending records; add no
  pending migration, recovery, or compatibility workflow.
- Update current service documentation and API contracts when implemented,
  including issuance examples and the operational denylist convention. Preserve
  ADR history with explicit supersession links.

## Acceptance criteria

- The existing authorized administrative flow issues a token with the three
  required claims; unauthorized callers cannot issue one.
- Missing/empty subjects and missing or nonpositive issuance lifetimes fail.
  Explicit lifetimes longer than 24h, including months, work.
- Verification rejects invalid signatures, wrong/missing audience, expired or
  missing expiration, and missing/empty subjects. Other credential kinds cannot
  authorize enrollment merely because the same signing key is trusted.
- A token enrolls multiple distinct hosts and permits otherwise-valid facts,
  including supplied realm and principal mode; ordinary host validation remains.
- Denylisting a subject rejects all its tokens and new issuance for that subject.
  Matching is exact and case-sensitive. A new subject can receive replacement
  credentials. Expiry/denylisting does not deactivate existing hosts.
- Audit identifies the verified subject. Multiple tokens may share it; the audit
  does not claim a unique token identity or log the raw credential.
- Identical retries retain the host ID, record, and audit history. Differing
  submissions cannot overwrite a host, including under concurrent creation.
- Public enrollment credentials do not cross into inventory, and no token store
  or use counter is needed. Enrollment authority cannot authorize other
  administrative operations or user SSH login.
- Removed credential paths are no longer accepted. Existing active hosts continue
  to work without a pending-record transition mechanism.
- Run `make build`, `make test`, and race tests appropriate to any changed
  concurrency-sensitive paths (`go test -race ./pkg/broker` if affected).

## Scope boundaries

Constraints, independent host configuration, and federation are separate sibling
tasks. This task does not wait for their design. Subject-denylist configuration
spelling and internal module organization are routine implementation choices;
the ADR defines the behavior.

---
# Log: 2026-11-16T04:45:01Z Codex

Created from mf2js8xw at the user's request; planning only.
