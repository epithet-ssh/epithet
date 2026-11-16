# ADR 0003: Control-issued unrestricted enrollment tokens

- Date: 2026-11-16
- Status: Accepted; not yet implemented.
- Scope: Managed enrollment token issuance, verification, attribution, and subject revocation.
- Supersedes: ADR 0002's pending-enrollment bearer and inventory-owned single-use
  credential decisions. Its provider boundaries and atomic creation-only write
  semantics remain applicable.

## Context

The current enrollment model has two credentials: a configured shared bearer
permits pending submissions, while an inventory-stored single-use token
preapproves a host and becomes its ID. Generated tokens have a maximum lifetime
of 24 hours. This couples credentials to inventory identity and requires separate
issuance, approval, and storage mechanisms.

The immediate need is a way to generate long-lived, reusable enrollment tokens
through the existing administrative flow. Control already has a signing key for
provider requests. It should own public enrollment authorization, while inventory
receives an authorized host write and owns persistence.

Earlier planning combined constrained grants, independent host configuration, and
inventory federation. The first implementation will support unrestricted
provisioning authority. Constraints and the other features are separate work;
we will not design a future authorization schema into this version.

## Decision

### Token format and authority

Issue signed JWTs with three required claims:

```json
{
  "aud": "epithet-enrollment",
  "exp": 1800000000,
  "sub": "production-provisioner"
}
```

- `aud` identifies the enrollment service. Issue the single string
  `epithet-enrollment`; enrollment verification requires that audience.
- `exp` is the required JWT expiration timestamp, in seconds since the Unix epoch.
  A token cannot authorize enrollment at or after expiration.
- `sub` is the required nonempty provisioning principal, supplied by the issuer.
  It identifies who the credential was issued to, not a unique token. Multiple
  tokens may share a subject. Subjects do not change the token's enrollment
  authority, except for the subject denylist below.

Use control's existing signing key. Enrollment verification checks the signature
against its configured key, audience, expiration, and nonempty subject before
accepting the credential. The fixed audience distinguishes enrollment from other
uses of the key. Signing keys separate deployments: deployments sharing a key
also share enrollment-token trust.

There is no custom `version`, `purpose`, nested authorization object, `iat`, or
`jti` in this first payload. There is no token database or token-use accounting.

Every accepted token grants unrestricted authority to enroll otherwise-valid host
facts, including names, labels, accounts, principal mode, and realm. Its holder
is a trusted provisioning principal. It cannot authorize administrative
replacement, other management operations, internal service requests, or user SSH
login. Existing host validation, user authentication, and Writ policy still apply.

### Issuance and lifetime

Preserve `epithet inventory token create` and the current administrative
authentication and authorization flow. Control issues the token, rather than
asking inventory to create and store a credential.

Require `--subject` and an explicit positive `--expires-in`. Remove the existing
24-hour policy cap and allow explicitly requested lifetimes of months; there is
no default lifetime or new arbitrary policy maximum. Expiration remains required.
For example:

```sh
epithet inventory token create --subject production-provisioner --expires-in 2160h
```

Tokens are reusable across hosts until expiration or subject revocation. Expiry
limits new enrollment, not the lifetime of existing host records or SSH access.

### Revocation by subject

Control configuration contains an enrollment-subject denylist. Match the verified
`sub` exactly and case-sensitively. Reject both issuance and enrollment for a
listed subject, regardless of which token it uses or when it was issued.

Apply denylist changes through normal control configuration and restart. All
control instances must receive the same configuration; this decision adds no
reload or distributed configuration mechanism. The list only grows as an
operational convention. Do not add history tracking to enforce monotonicity.
Replacement credentials for a revoked principal use a new subject.

Removing an entry would make that subject's unexpired tokens usable again. This
is why the convention is to retain entries. Revocation affects enrollment only;
existing enrolled hosts remain active. There is no individual token revocation,
per-subject issuance cutoff, or additional timestamp claim.

### Enrollment and audit

Control verifies the credential and host submission, then sends inventory an
authorized creation-only write. Do not forward the public token to inventory.
Preserve an independent random host ID locally across retries; it is neither the
token nor the subject, and knowing it conveys no authority.

Creation atomically produces an active record. An identical retry returns the
existing record unchanged; different facts conflict. Preserve these semantics
through the provider HTTP boundary and storage operation, including concurrent
requests. Enrollment never becomes administrative replacement.

Record the verified subject as the provisioning principal in enrollment audit
events. Attribution means that a credential issued to that subject was used;
it does not prove which person or machine possessed the bearer. The existing
unchanged-retry behavior, including no duplicate mutation audit event, remains.

### Replace the old mechanisms

Replace the pending-enrollment shared bearer and inventory-owned single-use
credentials, including their manual enrollment-approval and per-token revocation
flows. Existing active hosts remain active.

There is one deployment and it has no pending enrollments. Do not add pending
record migration, recovery, transition modes, or compatibility workflows. This
ADR records the intended replacement; it does not claim the code has changed.

## Alternatives and reasoning

- **Keep inventory-stored single-use credentials:** requires token persistence
  and atomic consumption, couples credentials to host identity, and does not
  satisfy reusable provisioning credentials. Control-signed tokens remove those
  responsibilities from inventory.
- **Keep only the configured shared bearer:** does not provide the requested
  administrative issuance, individual expiration, or named provisioning-principal
  attribution, and retains pending approval in the current design.
- **Implement constraints immediately:** requires a precise authorization language
  for omitted facts, patterns, accounts, labels, and destination identity. Those
  decisions are unnecessary for trusted unrestricted provisioning. Defer them
  rather than adding placeholder variants or guessing future claim shapes.
- **Use a label or unique token ID:** the requested audit identity is the
  provisioning principal, so standard `sub` is the appropriate claim. Requiring
  it makes attribution and subject revocation consistently available.
- **Revoke individual tokens or use per-subject time cutoffs:** adds token state
  or issued-at semantics. A configured subject denylist fits the accepted
  replacement workflow and needs neither.
- **Use a separate signing key or deployment-audience configuration:** would add
  configuration beyond the initial need. Reuse the existing key and require
  separate keys for independent deployments. Retiring that key invalidates all
  outstanding enrollment tokens and also requires updating provider trust.

## Consequences and deferred work

Control owns no per-token mutable state, but does have configured revocation
policy. Long-lived bearer credentials may enroll additional hosts until expiry
or denylisting, and those records survive token expiry or revocation. Host
retirement and SSH authorization remain separate decisions.

Unrestricted enrollment can assert any valid facts and destination identity;
it does not attest hostname ownership, cloud identity, or an SSH host key.
Constrained grants must settle destination-identity isolation before shipping.
Merely deriving a realm from an attacker-selected host ID is not a complete
isolation rule. The earlier mandatory control-derived realm proposal is
superseded for this unrestricted first phase, not resolved for restricted grants.

Future constraints must not silently reinterpret outstanding unrestricted tokens.
Their format and enforcement rules are deferred; v1 includes no speculative
extension schema. Independent host configuration and inventory federation are
not prerequisites for these tokens. Directory federation is also outside scope.

## Tracking

- [Parent plan](../../.tasks/open/mf2js8xw.md)
- [Implement unrestricted tokens](../../.tasks/open/f1ljvrhn.md)
- [Design constrained grants](../../.tasks/open/7oeid3c2.md)
- [Independent host configuration](../../.tasks/open/ttxxxg3i.md)
- [Inventory federation](../../.tasks/open/yrwrrbyf.md)

Implementation will update the existing service documentation and API contracts
to describe actual behavior. This ADR records an accepted design, while YATL owns
implementation status and deferred work.
