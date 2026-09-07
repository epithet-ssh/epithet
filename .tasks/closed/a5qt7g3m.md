---
yatl_version: 1
title: Extract inventory into a separately deployable service
id: a5qt7g3m
created: 2026-09-04T16:14:44.934795Z
updated: 2026-09-07T21:35:54.040025Z
author: Brian McCallister
priority: critical
tags:
- inventory
- security
- architecture
- host-enrollment
---

Implementation authorized September 7. The current contract is recorded in adr/inventory-service.md and docs/inventory.md. The following incorporates the later explicit-ID, identity-mode, and directory/host separation decisions.

Scope and sequence

1. This task delivers a working static inventory service. Move all inventory ownership and access out of policy, and make epithet server start inventory alongside CA and policy. There is no in-process inventory option inside policy.
2. Initial dynamic inventory follows: durable storage in 512htw8r, inventory administration/RBAC in 548x7rsk, registry in vpcj6szt, admission in v6hz0x82, and client integration in pmnvcb0h. SQLite or files on disk are the initial storage candidates; no backend is selected yet.
3. SCIM provisioning and persistent group-name bindings follow later in 8jwaf0d8. A SCIM-shaped resolver response does not require implementing SCIM provisioning in this task.

Service topology and authentication

All calls between the core Epithet services originate at the CA. The CA calls inventory and policy separately; inventory and policy never call each other. This is an intentional constraint that keeps the CA public key as the shared inter-service trust anchor.

Certificate flow:
- Client sends the certificate request and original OIDC token to CA.
- CA calls inventory with the token and target; inventory validates OIDC, maps the ID, and resolves directory and host records.
- CA calls policy with normalized authentication and inventory facts plus the connection, without the user token.
- Policy verifies the CA request, checks authentication expiry and fact binding, evaluates Writ, and returns bounded certificate parameters.
- CA validates those parameters and signs the certificate.

Reuse the existing pkg/serviceauth request-bound JWT mechanism. CA signs a separate token for each inventory or policy call; each token is bound to the appropriate audience, method, target, and body. The CA signature on the policy request covers the inventory facts as well as the original client request. The CA obtains facts from its configured inventory service and never promotes client-supplied inventory facts to trusted data. Authentication to inventory grants the CA the resolution-read capability, not blanket administrative authority.

Both services trust the CA public key. Existing public-key configuration supports literal keys, files, and HTTPS URLs; combined mode can pass the derived public key directly. No policy signing key, policy-to-inventory bearer token, mTLS scheme, ephemeral public-key discovery, or extra authentication-only policy round trip is part of this plan. The earlier policy-reader credential proposals are superseded.

OIDC validation, identity mapping, and login discovery belong to inventory. CA coordinates the calls and policy evaluates normalized facts; neither requires OIDC configuration. This supersedes the earlier shared-validation design. Authentication-age and reauthentication behavior remain follow-ups in 0zj196j0.

Direct client calls to inventory are a separate boundary: managed host enrollment uses admission authority; human administration uses OIDC plus inventory-owned RBAC. These are not inventory-to-policy or policy-to-inventory calls.

Resolver API direction

Use a versioned HTTP protocol independent of Writ's Go types and the storage schema. Resolve identity and requested host with internally coherent, separately revisioned directory and host snapshots. Return the user, memberships, host authorization resource, principal mode/domain metadata, and inventory revision. Keep the Writ-facing host projection separate from issuance metadata, including current shared principal-domain semantics.

The user object uses the SCIM User shape, group references, and the enterprise extension. Static YAML keeps explicit id and userName; group names remain literal IDs. Stable-id and verified-email semantics are preserved. Directory and host inventory have independent interfaces inside one service.

Implemented version 1 (see docs/inventory-api.yaml):
- POST /v1/resolve with the user token and host; CA authenticates with its request-bound service JWT, not a configured policy-reader token.
- Response contains version, host, authentication {id, expiresAt}, resolvedAt, directory {revision, user}, and inventory {revision, host}. Host separates resource (name, labels, accounts) from principal (mode, domain).
- Missing user/host returns null in a successful lookup and leads to structural denial. A lookup/storage/transport failure is an infrastructure error that fails closed, never an absent entity.
- Preserve account grounding: accounts:null means ungrounded, accounts:[] permits no accounts, and a list provides account grounding. Require the field so omission cannot silently broaden access.
- Bound request/response sizes and deadlines. The proposed first version uses no resolver cache and Cache-Control: no-store.
- resolvedAt is a lookup timestamp, not evidence that an upstream source is current. Finalize revision semantics and explicitly define freshness before supporting stale dynamic reads.

Pre-1.0 cleanup of Writ, its current implementation, and static configuration is acceptable where needed. Preserve intended authorization semantics rather than carrying unnecessary compatibility scaffolding. The managed duplicate-group union behavior in the current Writ spec must be replaced by the separately recorded binding design; static group names remain literal IDs.

Deployment and implementation outline

- Record the component/trust-boundary ADR and finalize the resolver plus CA-to-policy fact-carrying contracts before implementation.
- Extract static loading/validation into inventory, add epithet inventory, and configure CA with the inventory service endpoint.
- Add the bounded resolver client/server and adapt serviceauth for distinct service audiences without introducing another trust root.
- Move inventory lookup into CA; update policy to evaluate normalized facts with identity/target binding checks.
- Inventory owns OIDC validation, mapping, and discovery.
- Make epithet server supervise all three processes and wire private local channels. Support independent service deployment with the same contracts. Same-user subprocesses are not strong filesystem isolation from the CA key.
- Separate policy compilation/checking from inventory validation and carry policy content ID plus inventory revision into decision/audit records.
- Keep CA-URL-only host discovery; only configured managed inventory advertises capability-specific enrollment links. Static deployments expose no writable enrollment capability or enrollment link. Preserve one-command deployment and resource separation so future enrollment traffic cannot starve issuance reads.

Acceptance for this static phase

- All inventory is served by the inventory component; policy has no inventory client, storage access, or inventory credentials.
- Every core inter-service request originates at CA; inventory and policy authenticate it using the CA public key with request and audience binding.
- Only CA-authenticated requests reach policy decisions; no general public proxy to policy is exposed.
- CA forwards normalized authentication and inventory facts in one policy call; policy receives no OIDC token or provider settings.
- Separate and combined static deployments pass common resolver and issuance cases, including inactive/missing users, absent hosts, exact/pattern matching, account grounding, shared domains, and failure handling.
- An evaluation identifies independent directory and inventory revisions. Malformed or unavailable inventory responses fail closed as infrastructure errors.
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

---
# Log: 2026-09-07T21:10:36Z Brian McCallister

Started working.

---
# Log: 2026-09-07T21:10:36Z Brian McCallister

Implementation authorized September 7. Supersede static userName-as-ID with current explicit id/userName and stable-id/verified-email modes. Keep directory and host inventory as distinct lookup components within one inventory service, with separate revisions. Preserve CA-originated request-bound service authentication, private policy, and combined server supervision. Dynamic enrollment remains the next task.

---
# Log: 2026-09-07T21:35:54Z Brian McCallister

Completed the static extraction: inventory service and versioned SCIM-shaped resolver, independent directory/host interfaces and revisions, CA-originated audience-bound requests, independent OIDC verification and fact binding in policy, CA parameter checks, three-child server supervision, audit revisions, offline checks, migration/OpenAPI/ADR, and FreeBSD inventory service templates. make build plus explicit go build passed; make test passed; race checks passed for broker, CA, inventory service, policy handler, and combined server. Negative tests cover mismatched facts, missing accounts, audience separation, malformed/unavailable responses, redirects, and policy output bounds. API YAML references and sample config parsed; example offline checks passed. FreeBSD shell templates syntax-checked only; no live FreeBSD service or package run.

---
# Log: 2026-09-07T21:35:54Z Brian McCallister

Closed.
