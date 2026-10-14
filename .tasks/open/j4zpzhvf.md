---
yatl_version: 1
title: Add managed-directory reservations with first-login identity binding
id: j4zpzhvf
created: 2026-10-17T14:46:24.830913Z
updated: 2026-10-17T14:46:55.390055Z
author: Brian McCallister
priority: high
tags:
- directory
- oidc
- design
---

Implement a managed directory for providers without SCIM, using pre-created user reservations that acquire their stable authentication ID on first login. High priority, but explicitly deferred until the current big cleanup is finished. This task records the design discussion; it does not authorize starting implementation during that cleanup.

## Agreed direction

- This is a managed-directory model analogous to managed inventory. User data comes from record creation and authenticated provider data; SCIM provisioning is not required. No separate invitation-delivery or invitation-redemption flow is needed.
- Epithet owns this directory schema. Store an `id` field for the selected stable provider identifier, initially absent when it is not yet known. Do not name the field `sub`: the selected claim can be `sub`, `oid`, or an explicitly configured alternative.
- Call the reservation field `bootstrap`, not `bootstrap_email`. It holds the value used to match the first authenticated login and may be an email or another suitable provider identifier, such as an authenticated username.
- Distinguish the bootstrap-attribute mapping from the stable-ID mapping. Provider defaults or explicit configuration determine which authenticated attribute matches `bootstrap` and which supplies `id`. Do not assume standard OIDC discovery metadata declares these application-specific mappings.
- On first successful claim, store the selected stable identifier in `id` and consume `bootstrap`. Later logins resolve through the stable ID; bootstrap matching is not a permanent fallback. Email is not the permanent identity in this flow.
- Keep memberships and other administrator-provided attributes attached to the same reservation through claiming. Any database key required for these relationships is an internal storage detail, not a second public canonical Epithet identity.

## Required semantics

- Match only identity evidence authenticated by the configured trusted provider. Email bootstrapping requires verified-email evidence; other attributes need appropriate provider-specific ownership guarantees rather than trusting arbitrary profile text.
- Claim an eligible, unclaimed reservation and populate its ID atomically. Ambiguous matches, conflicting IDs, and competing claims must not transfer or duplicate access.
- After binding, a changed bootstrap value must not prevent the same stable identity from logging in. A different stable identity presenting the old bootstrap value must not reclaim that record.
- Unclaimed reservations have no usable stable authentication ID. First login establishes identity; it does not bypass ordinary account eligibility or authorization.

## Design work before implementation

Settle the minimal managed-record schema, creation/management interface, mapping configuration, and ownership of the persistent first-login mutation. Trace the existing CA/control authentication paths and directory fact boundary so resolution has consistent semantics. Compare materially different approaches where consequential; avoid a general account-linking framework or speculative recovery workflows.

Clarify how this feature relates to existing stable-id and verified-email modes: permanent email identity and one-time bootstrap matching are different behaviors. Do not silently reinterpret existing configuration.

Related task: ywxp1g89 tracks SCIM directory management and deferred manual CLI design. Coordinate shared management decisions without treating this new non-SCIM reservation feature as already implemented there.

## Provider research from discussion

GitHub is a motivating example for non-email bootstrapping, not an agreed requirement to add a native GitHub authentication adapter. GitHub human login uses OAuth plus the authenticated-user API; its Actions OIDC provider identifies workflows. The user API distinguishes mutable `login` from durable numeric `id`. A display name is not a suitable bootstrap identifier. If using an OIDC broker, verify the broker's actual claims and mappings.

References:
- https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
- https://docs.github.com/en/rest/users/users
- https://docs.github.com/en/actions/reference/security/oidc

## Validation when implemented

Cover first claim, subsequent stable-ID login, bootstrap value changes, rejection of unverified or unsuitable evidence, ambiguous reservations, ID collisions, concurrent claims, and preservation of memberships. Run repository-required build/test checks and concurrency checks appropriate to the implementation.

---
# Log: 2026-10-17T14:46:24Z Brian McCallister

Created task.
