---
yatl_version: 1
title: Design SCIM directory management and CLI access through control
id: ywxp1g89
created: 2026-10-13T15:43:29.263132Z
updated: 2026-10-13T15:45:10.537899Z
author: Brian McCallister
priority: low
tags:
- design
- control
- directory
- scim
---

# SCIM directory management and CLI access

Deferred, lower-priority design work split from inventory task `s9cqey45`.
Manual directory user creation and editing must not block inventory management.
Implementation is not authorized by this task.

## Agreed direction

- SCIMv2 is the directory-management API, including user/group listing. Do not
  introduce a parallel user/group management API.
- Control fronts SCIM. The existing provisioning token becomes an optional shared
  secret; OIDC users with directory-admin grants can invoke the same operations.
  Omitting the secret disables that authentication path, not authorized OIDC access.
- CLI access uses OIDC through the existing agent. Control authenticates private
  provider requests and preserves human actor identity.
- Commands belong under `epithet directory`, not `control` or `scim`.
- Accept names when unique, rejecting absent or ambiguous matches. Retain explicit
  ID addressing. Do not put Writ selectors/filter expressions on the CLI.
- Keep the built-in directory's single SCIM `userName`, projected to fact `name`
  as `[userName]`. Do not expand storage to multivalued names; other providers
  may still supply multiple names through the general fact API.
- Proposed creation shape discussed and accepted:
  `epithet directory users create NAME [--id ID]`. NAME supplies `userName`;
  `--id` supplies authentication identity via SCIM `externalId`, defaulting to NAME.
  The server still assigns a separate SCIM resource ID.

## Identity mapping and deferred CLI discussion

Manual creation only works when the chosen ID equals the verified OIDC claim
used for directory lookup. Existing options include stable-id (sub by default,
Entra oid by default), verified-email, and an explicit top-level user-id-claim.
Defaulting ID to NAME is meaningful only when that value matches the configured
mapping. Operator setup and documentation need further discussion; no new mapping
or enrollment workflow was agreed. An invite flow was explicitly NOT proposed
by the user and is outside this task.

The suggested minimal CLI covers list/show/create/update/delete for users and
groups, plus group add-member/remove-member. This catalogue is still a proposal.
Unique-name lookup is agreed; exact targeting flags remain open. Explicit groups
were recommended, but the group lifecycle discussion was not completed.

The user proposed `-e/--edit` to open a prefilled YAML document shaped like SCIM
core and enterprise-extension attributes, allowing additional attributes.
Template details and additional-attribute preservation/storage remain unresolved.
The earlier repeatable-name and separate-user-name flags were superseded by the
single-name decision. Do not implement arbitrary attribute storage merely because
an editor can accept it.

## Provider boundary and remaining decisions

Authorization fact lookup stays separate from directory management. ADR 0001
removed historical group binding/reconciliation. Group names and identities now
follow the current provider facts. Do not restore binding operations.

Consider whether ordinary user facts suffice for administrator authorization;
removing the separate actor/revision protocol was recommended but not yet agreed.
The current backend no longer checks the authorization revision formerly used
for rebinding. Determine audit inspection separately from standard SCIM operations.

Provisioning transport alternatives previously considered:

1. Retain the current signed SCIM-in-JSON tunnel: smallest immediate change, but
   exposes a custom envelope and header allowlist.
2. Advertise a SCIM endpoint and forward signed HTTP: preferred exploration
   direction, requiring precise target and conditional-header integrity rules.
3. Move SCIM adaptation into control and invent provider user/group operations:
   enlarges the private API and conflicts with the agreed SCIM management direction.

The current signature binds method, target, and body, not arbitrary headers.
The tunnel protects If-Match inside the signed body; any direct SCIM hop must
preserve that integrity. This is unresolved design, not implementation approval.

Discovery remains optional for a data-only directory provider. Coordinate shared
control/discovery conventions with inventory task `s9cqey45`, without making
inventory wait for manual directory administration. Signed OPTIONS and Link-based
capabilities remain a proposal; exact relations, failure semantics and Unix
addressing are not settled.

## Design record

The user requested discussion followed by ADR 0002 for the settled management
interface, alternatives and rationale. Coordinate that record with `s9cqey45`;
no ADR has been written and deferred directory work must not block inventory.
Implementation planning and sequencing stay in YATL.

The original combined exploration and conversation log remain in the history of
`s9cqey45`. Its older binding proposals were superseded by ADR 0001 and the SCIM
boundary above.

---
# Log: 2026-10-13T15:43:29Z Brian McCallister

Created task.

---
# Log: 2026-10-13T15:45:10Z Brian McCallister

Split from s9cqey45 at user request. Preserved agreed SCIM/control authentication, agent-backed CLI direction, unique-name addressing, single-name creation and OIDC mapping discussion. Manual directory administration is deferred; inventory is higher priority. Implementation remains unapproved.
