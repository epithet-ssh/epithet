---
yatl_version: 1
title: Design stateless host enrollment, independent configuration, and federated inventory
id: mf2js8xw
created: 2026-10-24T04:13:35.453651303Z
updated: 2026-10-24T04:15:03.874847568Z
author: Brian McCallister
priority: medium
tags:
- design
- control
- inventory
- enrollment
---

# Planning status

Capture the host-enrollment and inventory-federation design discussion. This is
planning only: the user explicitly withheld implementation authorization. Existing
flows, CLI names, and UX are not requirements to preserve. Settle the open
contracts before implementation; do not infer authorization to build cloud or
hypervisor providers from the deployment examples below.

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

## Agreed direction

### Separate local configuration from managed enrollment

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

### Simplify managed enrollment authorization

- Manual enrollment approval is no longer needed. Issuing an enrollment grant
  is the authorization decision; successful enrollment creates an active host.
  This concerns host-enrollment review, not other Writ authorization requirements.
- Use one enrollment credential model instead of separate pending-submission
  and single-use preapproval mechanisms.
- The working design is a self-contained signed, reusable, time-bounded grant
  issued and verified by control. Embed its constraints in the signed payload;
  a reference to a mutable stored template would introduce state again.
- Host IDs are independent of enrollment tokens. Single-use and maximum-use
  enforcement require mutable shared accounting and are not part of the
  stateless direction. Do not add a token database merely to retain the old UX.
- Constraints describe permitted host facts through patterns, rather than
  special-case options such as hostname suffixes or a template of fixed values.
  Examples discussed were `--name '*.workers.example.com' --account '*'`.
  These are illustrative issuing options, not a finalized CLI.
- Control validates the grant and the submitted facts. Inventory receives an
  authorized host write, not the public enrollment credential.
- Expiration governs new enrollment, not the lifetime of existing inventory
  records or user SSH access. User authentication and Writ continue to decide
  certificate issuance; an account wildcard is not a grant of login to everyone.

### Preserve creation-only enrollment semantics

- Keep a stable host ID across retries. Enrollment can create a missing record,
  return an identical existing record unchanged, and reject differing facts.
  It cannot overwrite a host or become administrative replacement.
- Existing enrollment PUT already supplies these semantics through atomic
  `WriteConditions.CreateOnly`. Moving creation to POST is not necessary for
  this security property. Preserve the distinction in authorization and storage.

### Control destination identity

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

### Federate inventory lookups with availability

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

### Support partial control-plane capabilities

- A provider may support lookup and listing without supporting enrollment or
  other mutations. Cloud-backed inventory is a concrete example.
- Build on existing capability advertising instead of inventing it anew:
  public control already advertises capabilities; inventory providers already
  advertise resource templates with signed OPTIONS and Link-Template.
- Current discovery requires the complete records/tokens/audit relation set and
  infers `enroll` from its presence. The current contracts do not cleanly express
  a listing-only provider. Extend the granularity and relax the all-or-nothing
  assumption; the precise advertisement contract remains open.

## Threat model and accepted limits

Trust authorized grant issuers, control, the CA, and configured inventory
authorities. Treat enrolling hosts and their submitted facts as potentially
malicious; a provisioning or fleet credential can be copied or compromised.

The grant delegates authority to assert facts. It does not prove ownership of a
hostname, cloud-instance identity, or an SSH transport host key. Bound both policy
facts and destination identity, preserve creation-only writes, and ensure an
enrollment grant cannot authorize user login, administration, or internal service
operations. Signed grant contents are not inherently confidential.

A reusable bearer may enroll additional in-scope hosts until expiration. Record
creation during that window can have effects beyond expiration. Strict counts
and immediate individual revocation cannot be promised without mutable shared
policy. Token expiry is not a substitute for host retirement or changing access
policy. Realm values and host IDs are not credentials; knowing an ID cannot
authorize replacement of its record.

## Remaining open questions

1. **Grant contract and issuing authority:** exact payload, signing-key ownership,
   enrollment purpose and deployment/audience binding, issuer authorization,
   permitted lifetime/defaults, and how provisioning obtains fresh grants.
   Decide whether individual revocation is needed before adding any state.
2. **Constraint semantics:** which fields support patterns; reuse of existing
   hostname/account matchers; repeated-pattern behavior; required fields and
   omitted constraints; missing or extra label keys; canonicalization; and the
   distinction between account lists, empty lists, and unrestricted accounts.
   Every way to express facts must remain within the grant. Do not assume the
   earlier fixed-label template proposal is the chosen model.
3. **Principal identity:** exact principal-mode authorization, deterministic realm
   encoding/domain separation, and stable identity scope across independent
   providers/deployments. Specify how a shared realm is authorized and keep that
   choice explicit. Define deletion/recreation and ID-reuse semantics; deterministic
   derivation recreates the same identity when its inputs are reused.
4. **Configure/enroll contract:** final input and CLI names, which principal facts
   must be explicit, bootstrap CA trust via `--ca`, and the shared internal
   interface. Settle registration/configuration ordering, rerun behavior, and
   failure semantics. Fully offline CA-key input was raised but not decided or
   requested. Current workflow is not sacrosanct.
5. **Federation placement/configuration:** multiple endpoints in the existing fact
   client versus a separate federating service, provider identification, and
   authentication/key configuration. Direct client composition was suggested,
   but placement has not been selected. Specify cancellation, bounded lookup
   lifetime, and the no-success result when some providers fail versus all report
   absence. Any collision diagnostics must preserve the agreed availability.
6. **Partial capabilities:** represent supported operations separately from their
   resource locations using the existing discovery foundation. Decide provider-
   scoped versus aggregate public advertising, and how the CLI selects an
   enrollment or management target among multiple providers.
7. **Federated listing:** aggregation, provider-local IDs/cursors, pagination,
   unavailable or non-listing providers, and how to represent incomplete coverage.
   Listing is desired; the detailed cross-provider behavior is not settled.
8. **Existing installations:** identify changes to pending/review commands,
   single-use token storage, wire contracts, and local identity/configuration.
   Discuss any compatibility or migration requirement before designing support;
   none was authorized by this planning conversation.

## Deferred directory work

The same partial-capability model may apply to directories. Directory federation
and multiple-IdP support are less pressing and are not part of the inventory
implementation scope. Multiple IdPs do not necessarily require multiple
directories. A later design must address issuer-scoped identity, intentional
account linking, group identity, and authority ownership rather than assuming
inventory name semantics carry over unchanged. No directory federation contract
was selected. Existing directory management work is tracked in `ywxp1g89`.

## Related work and current code

- `s9cqey45` (closed): implemented inventory management and provider discovery;
  preserve its implementation history, while this task revisits the lifecycle
  and partial-capability assumptions.
- `ywxp1g89` (open): SCIM directory management and CLI work; directory federation
  is a distinct deferred design consideration.
- `q06t72c8` (open): ambiguity diagnostics inside a provider. Do not confuse its
  existing local lookup rules with cross-provider availability decisions here.
- `pkg/facts/control/server.go`: public provider capability aggregation.
- `pkg/facts/control/inventory.go`: current complete relation-set requirement.
- `pkg/facts/inventory/rules.go` and `store.go`: enrollment validation and
  creation-only write contract.
- `cmd/epithet/host_enroll*.go`: existing combined local setup and registration.

Next step: resolve the contracts above and turn agreed decisions into scoped
implementation work only when the user requests implementation. No production
code, tests, schemas, command behavior, or provider adapters change in this task's
planning update.

---
# Log: 2026-10-24T04:13:35Z Brian McCallister

Created task.
