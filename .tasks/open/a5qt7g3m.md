---
yatl_version: 1
title: Extract inventory into a separately deployable service
id: a5qt7g3m
created: 2026-09-04T16:14:44.934795Z
updated: 2026-09-05T16:54:13.283320Z
author: Brian McCallister
priority: critical
tags:
- inventory
- security
- architecture
- host-enrollment
---

Agreed design from the September 4-5 discussion. This task records the plan; implementation is not authorized by recording it.

Scope and sequence

1. This task delivers a working static inventory service. Move all inventory ownership and access out of policy, and make epithet server start inventory alongside CA and policy. There is no in-process inventory option inside policy.
2. Initial dynamic inventory follows: durable storage in 512htw8r, inventory administration/RBAC in 548x7rsk, registry in vpcj6szt, admission in v6hz0x82, and client integration in pmnvcb0h. SQLite or files on disk are the initial storage candidates; no backend is selected yet.
3. SCIM provisioning and persistent group-name bindings follow later in 8jwaf0d8. A SCIM-shaped resolver response does not require implementing SCIM provisioning in this task.

Service topology and authentication

All calls between the core Epithet services originate at the CA. The CA calls inventory and policy separately; inventory and policy never call each other. This is an intentional constraint that keeps the CA public key as the shared inter-service trust anchor.

Certificate flow:
- Client sends the certificate request and original OIDC token to CA.
- CA validates OIDC and extracts the identity needed for the inventory lookup.
- CA calls inventory to resolve that identity and the requested host together.
- CA calls policy once with the original token, connection, and the inventory result including its revision.
- Policy validates OIDC itself, checks that the supplied facts correspond to the authenticated identity and requested target, evaluates Writ, and returns bounded certificate parameters.
- CA validates those parameters and signs the certificate.

Reuse the existing pkg/serviceauth request-bound JWT mechanism. CA signs a separate token for each inventory or policy call; each token is bound to the appropriate audience, method, target, and body. The CA signature on the policy request covers the inventory facts as well as the original client request. The CA obtains facts from its configured inventory service and never promotes client-supplied inventory facts to trusted data. Authentication to inventory grants the CA the resolution-read capability, not blanket administrative authority.

Both services trust the CA public key. Existing public-key configuration supports literal keys, files, and HTTPS URLs; combined mode can pass the derived public key directly. No policy signing key, policy-to-inventory bearer token, mTLS scheme, ephemeral public-key discovery, or extra authentication-only policy round trip is part of this plan. The earlier policy-reader credential proposals are superseded.

OIDC validation is a shared capability rather than a responsibility exclusive to one service. Retain the original token for policy evaluation; policy may impose stronger requirements on authentication evidence than CA validation. Keep the implementation concrete and OIDC-only now, while leaving room for an explicit SAML flow later. Do not introduce a generic authentication framework. Authentication-age and reauthentication behavior are follow-ups in 0zj196j0.

Direct client calls to inventory are a separate boundary: managed host enrollment uses admission authority; human administration uses OIDC plus inventory-owned RBAC. These are not inventory-to-policy or policy-to-inventory calls.

Resolver API direction

Use a versioned HTTP protocol independent of Writ's Go types and the storage schema. Resolve identity and requested host in one coherent snapshot. Return the user, memberships, host authorization resource, principal mode/domain metadata, and inventory revision. Keep the Writ-facing host projection separate from issuance metadata, including current shared principal-domain semantics.

The user object uses the SCIM User shape, including schemas, userName, active, userType, group references, and the enterprise User extension for department and organization. For static inventory the name IS the ID: userName supplies user.id, and group names supply membership value/display. Do not require extra user/group IDs or declarations in YAML. Managed SCIM identity and name-binding lifecycle is separate follow-up work.

Working proposal, not a finalized wire specification:
- POST /v1/resolve with identity and host; CA authenticates with its request-bound service JWT, not a configured policy-reader token.
- Response contains revision, resolvedAt, user, and host. Host separates resource (name, labels, accounts) from principal (mode, domain).
- Missing user/host returns null in a successful lookup and leads to structural denial. A lookup/storage/transport failure is an infrastructure error that fails closed, never an absent entity.
- Preserve account grounding: accounts:null means ungrounded, accounts:[] permits no accounts, and a list provides account grounding. Require the field so omission cannot silently broaden access.
- Bound request/response sizes and deadlines. The proposed first version uses no resolver cache and Cache-Control: no-store.
- resolvedAt is a lookup timestamp, not evidence that an upstream source is current. Finalize revision semantics and explicitly define freshness before supporting stale dynamic reads.

Pre-1.0 cleanup of Writ, its current implementation, and static configuration is acceptable where needed. Preserve intended authorization semantics rather than carrying unnecessary compatibility scaffolding. The managed duplicate-group union behavior in the current Writ spec must be replaced by the separately recorded binding design; static names remain literal IDs.

Deployment and implementation outline

- Record the component/trust-boundary ADR and finalize the resolver plus CA-to-policy fact-carrying contracts before implementation.
- Extract static loading/validation into inventory, add epithet inventory, and configure CA with the inventory service endpoint.
- Add the bounded resolver client/server and adapt serviceauth for distinct service audiences without introducing another trust root.
- Move inventory lookup into CA; update policy to evaluate the supplied facts and original token with identity/target binding checks.
- Share OIDC validation as appropriate; no extra policy call is required to extract identity.
- Make epithet server supervise all three processes and wire private local channels. Support independent service deployment with the same contracts. Same-user subprocesses are not strong filesystem isolation from the CA key.
- Separate policy compilation/checking from inventory validation and carry policy content ID plus inventory revision into decision/audit records.
- Keep CA-URL-only host discovery; only configured managed inventory advertises capability-specific enrollment links. Static deployments expose no writable enrollment capability or enrollment link. Preserve one-command deployment and resource separation so future enrollment traffic cannot starve issuance reads.

Acceptance for this static phase

- All inventory is served by the inventory component; policy has no inventory client, storage access, or inventory credentials.
- Every core inter-service request originates at CA; inventory and policy authenticate it using the CA public key with request and audience binding.
- Only CA-authenticated requests reach policy decisions; no general public proxy to policy is exposed.
- CA forwards the original OIDC token and trustworthy inventory facts in one policy call; policy independently validates the token and rejects mismatched facts.
- Separate and combined static deployments pass common resolver and issuance cases, including inactive/missing users, absent hosts, exact/pattern matching, account grounding, shared domains, and failure handling.
- An evaluation uses one coherent inventory revision. Malformed or unavailable inventory responses fail closed as infrastructure errors.
- epithet server remains the supported one-command path. Managed enrollment and the broader five-minute enrollment experience are follow-on acceptance, not prerequisites for completing static extraction.

---
# Log: 2026-09-04T16:14:44Z Brian McCallister

Created task.

---
# Log: 2026-09-04T23:45:17Z Brian McCallister

Started working.

---
# Log: 2026-09-04T23:45:17Z Brian McCallister

Agreed sequence: first extract static inventory into a working service with local and remote resolution; then build initial dynamic inventory, likely backed by SQLite or disk files. Database choice remains open. Managed provisioning and enrollment remain follow-on work.

---
# Log: 2026-09-04T23:47:57Z Brian McCallister

Stopped working.

---
# Log: 2026-09-04T23:47:57Z Brian McCallister

Clarification: this is a design discussion only; implementation was started prematurely and the code edits have been reverted. Discuss the static service shape and authentication using existing Epithet mechanisms before implementing. No mTLS decision has been made.

---
# Log: 2026-09-05T16:54:13Z Brian McCallister

Recorded the agreed CA-originated service topology and static-first scope. CA resolves inventory and includes facts plus the original OIDC token in one policy request; both services trust its request-bound JWTs. Replaced the in-process inventory, policy-reader bearer token, and mTLS directions. Linked dynamic storage, administration/enrollment, SCIM bindings, and authentication-evidence follow-ups; wire details still marked as proposals.
