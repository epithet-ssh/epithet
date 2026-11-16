---
yatl_version: 1
title: "Port SCIM provisioning to control-issued signed tokens"
id: ldh8oxeq
created: 2026-11-16T19:39:22Z
updated: 2026-11-16T19:39:22Z
author: Codex
priority: medium
tags:
- control
- scim
- authentication
---

## Status and scope

Deferred work, filed at the user's request. Implement in a separate change from
[f1ljvrhn](../closed/f1ljvrhn.md), the enrollment-token implementation in jj change
`vmyyktul`. This task does not authorize SCIM implementation in that change.

## Intended model

Use the control-issued signed-token model from
[ADR 0003](../../docs/adr/0003-control-issued-enrollment-tokens.md) for SCIM
provisioning credentials:

- Sign with control's existing Ed25519 key.
- Use the minimal `aud`, `exp`, and nonempty `sub` claims, with `aud: "scim"`.
- Require an explicit positive lifetime and support subject revocation.
- Attribute provisioning audit events to the verified subject, replacing the
  generic `scim` actor for this credential path.
- Grant the authority currently provided by the SCIM provisioning secret;
  preserve the OIDC directory-administrator path.
- Keep public credentials at control. Providers continue receiving authenticated
  service requests carrying the verified actor.

Share signing and verification within control where it simplifies the two actual
uses. Each endpoint verifies its own expected audience. No token database,
per-token use tracking, general authorization framework, or new scopes are part
of this model.

## Decisions to settle before implementation

- Who may issue SCIM credentials, and through which administrative command/API?
- Does subject revocation apply across token audiences or separately per audience?
- Do signed credentials replace the configured SCIM secret, or coexist with it?
  Do not invent a compatibility or migration workflow before this is decided.

## Validation and documentation

Cover issuance authorization, signature/audience/expiry/subject checks, subject
revocation, and audit attribution. Show that enrollment credentials cannot
provision SCIM and SCIM credentials cannot enroll hosts. Preserve existing OIDC
administration and provider behavior. Update SCIM configuration and operational
documentation for the selected credential lifecycle.

Related: [directory management](ywxp1g89.md). Host-enrollment audience naming was
also discussed, but changing it is not part of this SCIM task.

---
# Log: 2026-11-16T19:39:22Z Codex

Filed the agreed SCIM signed-token direction and unresolved decisions. No code or
configuration changed; implementation is deferred to its own change.
