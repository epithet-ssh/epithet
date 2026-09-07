---
yatl_version: 1
title: Audit CA, inventory, and policy API boundaries
id: thbfp6pt
created: 2026-09-08T02:31:01.205849Z
updated: 2026-09-08T02:35:31.433207Z
author: Brian McCallister
priority: high
tags:
- api
- architecture
---

Audit completed against the current working copy. Review only; no production API changes made. Scope: public client-to-CA issuance and login discovery; CA-to-inventory lookup/discovery; CA-to-policy evaluation; status/error propagation into the public client. Broker IPC, dynamic enrollment, and general transport hardening are outside this pass.

Agreed boundaries

- Inventory validates OIDC, maps identity, and supplies normalized directory and host facts.
- CA coordinates inventory and policy; policy receives no user bearer token or OIDC settings.
- Successful public issuance returns only certificate. Directory/inventory/policy revisions remain private audit metadata and are not encoded into certificates.
- User and host facts remain separately owned within the inventory service. Static file configuration is inventory.static. Keep the one-command server deployment.

Findings

1. Public error boundary is not explicit. pkg/ca/ca.go:205 wraps every non-200 policy response with its original status and body, and pkg/caserver/caserver.go:181 copies it to the client. Infrastructure errors at :184 also include PolicyURL and raw error details; discovery at :80 includes raw upstream errors. Thus internal diagnostics and policy labels can cross the public boundary. This behavior predates extraction. Recommendation: CA owns public error classification and safe public messages; backend diagnostics stay in server logs. Decide which policy-denial detail is intentionally client-visible.

2. Service authentication and end-user authentication are conflated for policy. Policy returns 401 when the CA service JWT fails verification; CA forwards 401; caclient treats it as InvalidTokenError and broker forces user-token refresh. Inventory already treats service authentication failure as 403 internally and converts it to infrastructure failure at CA. Recommendation: explicitly distinguish these failure classes at each boundary. This predates extraction but becomes more confusing now that policy performs no end-user authentication.

3. Inventory wire shape imports unnecessary SCIM protocol structures. pkg/inventoryapi/protocol.go:13-41 defines schema URNs, the enterprise URI property, and group value/display objects. Resolver duplicates each static group into value and display; evaluator reads only value. Recommendation: remove schemas, flatten department/organization, and represent group membership with strings. Static/directory domain types already use that simpler representation. Future SCIM adapters should translate at their boundary.

4. Unused metadata and envelope coupling. resolvedAt is set and checked for nonzero but has no consumer, freshness semantics, or issuance-log use. PolicyRequest embeds the entire inventory Resolution, including inventory protocol version, timestamp, and revisions, rather than just the normalized facts needed for a decision. PolicyResponse echoes directory and inventory revisions, but CA overwrites them from the original lookup. Recommendation: keep revisions for CA audit; remove unused timestamp and redundant policy echo; define a policy input independent of inventory transport metadata.

5. Certificate assembly is duplicated across policy and CA. Policy returns id, certificate identity, derived principal(s), and authentication NotAfter. CA already has/derives these, rejects differing id/identity/principals, and clamps NotAfter against inventory expiry. This is an inherited policy-output design exposed by the extraction, not a newly introduced authority bypass. Design proposal for discussion: policy returns authorization outcome, allowed lifetime/extensions, policy ID, and any intentionally policy-owned tighter absolute bound; CA assembles identity and principal from trusted inventory/connection facts. Preserve all current target binding and lifetime checks during any refactor. TTL vs absolute policy deadline semantics need an explicit decision, not automatic removal of notAfter.

6. Endpoint/version cleanup remains unapplied. Inventory still serves POST /v1/resolve despite the discussion favoring POST / plus GET / discovery. It also carries a body version. A single protocol-version mechanism is defensible for incompatible services; two are not necessary. Root routing under reverse-proxy prefixes should be handled consistently rather than broadening this into a routing redesign.

7. Existing incomplete public pending status: library evaluator can emit 202 with plain text, CA forwards it, and public caclient treats it as InvalidRequestError. Built-in CLI cannot currently register requirement plugins, so this is not an active static CLI flow. Already covered by 0zj196j0; do not claim a supported public pending protocol or add stateful workflows as part of this cleanup.

Explicitly retained / intentional

- Authentication id and expiry; record/target binding; active status; account null versus empty-list semantics; principal mode/domain for certificate construction; independent revisions for audit.
- Bound request sizes, deadlines, and request-bound CA service JWTs with distinct audiences.
- Discovery intentionally publishes issuer/client ID and also client_secret when configured. This is existing behavior and an existing follow-up; it must not be described as private configuration. Do not change OAuth client behavior implicitly in API cleanup.

Evidence

Read handlers, request/response types, their consumers, and parent revision to distinguish existing behavior from extraction additions. A temporary /tmp/epithet-api-audit.go probe used fake local inventory/policy services and a generated test key. It confirmed:
- private policy 401 -> public 401 with the service-credential error text;
- private policy 500 -> public 500 with a synthetic internal database path;
- private policy 202 -> public 202 with pending text (client handling verified by code inspection).
No real credentials, external services, or production data were involved. No repository source or API behavior changed in this audit.

Next step is agreement on the minimal request/response contracts, especially policy output ownership and public error messages. Implementation is not included in this audit task.

---
# Log: 2026-09-08T02:31:01Z Brian McCallister

Created task.

---
# Log: 2026-09-08T02:32:02Z Brian McCallister

Completed focused API audit and local error-propagation probe. Findings and proposed cleanup boundaries are in the task body. No production code or API behavior changed; contract changes remain for discussion.

---
# Log: 2026-09-08T02:32:02Z Brian McCallister

Closed.

---
# Log: 2026-09-08T02:35:09Z Brian McCallister

Filed high-priority remediation tasks: ms54kqbp, kkr7vee5, hmh7yb8s, v0n79ah8, 89sc9825, 20c03jnp, twperd14. Raised existing bootstrap client_secret review hv3622e5 to high. Separated pending handling from 0zj196j0; envelope cleanup depends on settling policy output ownership. No production changes made.

---
# Log: 2026-09-08T02:35:31Z Brian McCallister

User resolved the client_secret question: intentional distribution is required for supported Google clients and is not a leak. Closed hv3622e5 without implementation changes. The seven other high-priority API cleanup tasks remain.
