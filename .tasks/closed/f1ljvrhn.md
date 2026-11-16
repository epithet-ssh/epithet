---
yatl_version: 1
title: "Implement control-issued unrestricted enrollment tokens"
id: f1ljvrhn
created: 2026-11-16T04:45:01Z
updated: 2026-11-22T00:06:57Z
author: Codex
priority: medium
tags:
- control
- inventory
- enrollment
---

Parent: [mf2js8xw](../open/mf2js8xw.md).

# Status and decision

Implemented on 2026-11-16 following the user's explicit implementation request,
in jj change `vmyyktul` on design-documentation parent `vuknzswp`.

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


---
# Log: 2026-11-16T05:05:22Z Codex

Implemented ADR 0003. Control issues reusable JWTs with only aud, exp, and sub,
using its existing signing key and administrative authentication. Issuance requires
subject and explicit positive lifetime; 90-day issuance is covered through the
real broker-backed CLI. Exact, case-sensitive denied-subject
configuration rejects issuance and enrollment after normal restart.

Enrollment sends the JWT only to control and persists an independent random host
ID locally. Signed provider POSTs carry the verified subject,
atomically create active records, preserve identical retries and audit history,
and conflict on different facts. The provider owns host validation and
normalization; control forwards host facts without a built-in inventory dependency.

Removed pending/shared-bearer enrollment, single-use token storage and provider
resources, approval/denial commands, and individual revocation. SQLite version 6
retires the credential table while preserving existing active hosts and audit;
no pending migration or compatibility workflow was added. Updated service/API
documentation and ADR supersession status. Constraints, independent host
configuration, and federation remain deferred in sibling tasks.

Validated with make -B build, make test, dependency architecture tests, and
race tests for control, provider HTTP, inventory storage, service authentication,
and broker. The Makefile reports missing svu in this environment; the fresh build
and tests still succeed.

---
# Log: 2026-11-16T17:00:51Z Codex

Addressed design review: returned validation to inventory.Host and removed the
internal/hostinput package. Validation owns name normalization without mutating
shared caller slices. Consolidated edit validation and simplified enrollment
signer construction to use the configured key directly. Removed import
whitelists and domain/YAML dependency bans that imposed requirements beyond
provider independence; retained checks for concrete service/storage coupling.
No enrollment behavior or deferred feature scope was added.

---
# Log: 2026-11-16T17:06:30Z Codex

At the user's request, restricted enrollment signing to Ed25519 and fixed JWT
verification to EdDSA. Removed enrollment's algorithm selection and multi-key
support tests. General service authentication and SSH key handling remain
unchanged; simplifying those would be separate work. Updated the ADR and service
documentation to state the enrollment key requirement.

---
# Log: 2026-11-16T19:03:25Z Codex

Applied the agreed independent-review corrections. Removed redundant host
validation and normalization from control, restored the original dependency
tests and Host.Validate implementation, and restored copies before provider
validation. Enrollment signing and verification now live privately in control.
Removed enrollment-token checks from admin and SCIM authentication; a real OIDC
validator covers rejection through their existing authentication paths. Integration
coverage checks that control forwards hostname casing and order unchanged.

Removed the deleted-command/flag test, moved the denylist CLI field to the old
enrollment configuration position, and corrected provider documentation, including
the stale actor table and the loss of inventory token-issuance audit events.
Creation-only protocol semantics, expiry guards, schema migration, audit subject
format, and the configured-inventory requirement for issuance remain unchanged.

Validated with make -B build, make test (including the restored dependency
guardrails), and race tests for control, provider HTTP, inventory storage,
service authentication, and broker. All passed.

---
# Log: 2026-11-17T02:42:41Z Codex

Renamed EnrollmentDeniedSubjects to DeniedSubjects and the CLI/configuration key
to denied-subject at the user's request. Updated callers, tests, and documentation;
current enrollment denial behavior is unchanged.

---
# Log: 2026-11-17T03:23:10Z Codex

Changed enrollment to POST at the user's request, retaining client-generated
IDs. The public request uses POST to /manage/HOST_ID and control forwards a
signed POST to the discovered provider record URL for that ID. Removed the
createOnly wire field and body discriminator. The internal storage creation-only
condition, atomic identical-retry/conflict behavior, and administrative POST/PUT
operations retain their existing semantics. Updated protocol documentation and
existing HTTP, client, and enrollment tests. The handler refactor remains deferred.

Validated with make -B build, make test, and race tests for control, provider HTTP,
inventory storage, and broker. All passed.

---
# Log: 2026-11-18T03:21:23Z Codex

Unified host creation for `inventory add` and `host enroll`. Both commands
choose the host ID and POST the same `create` request. Inventory administrators
and enrollment subjects may submit exact or wildcard names. The provider uses
one atomic creation-only write and records the authenticated actor on the
`create` event. Identical retries preserve the record and audit history.

The fresh build, full test suite, and race tests for control, provider HTTP,
inventory storage, and broker passed.

---
# Log: 2026-11-22T00:02:29Z Codex

Enrollment now uses the same signing key types as control's provider requests.
Both protocols select the JWT algorithm from the configured key and check the
signature before applying their own claim rules. Verified enrollment, service
signatures, and directory-only startup with Ed25519, RSA, ECDSA P-256, and
ECDSA P-384. The fresh build, full suite, and serviceauth, control, and broker
race tests passed.

---
# Log: 2026-11-22T00:06:57Z Codex

Control now checks the provider's returned host ID on creation using the
existing read check. A regression test confirmed that a mismatched ID used
to reach the caller as HTTP 200 and now returns HTTP 503 with no host record.
The fresh build, full test suite, and control race tests passed.
