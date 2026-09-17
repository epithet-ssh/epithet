# SCIM directory provisioning

Epithet inventory supports a managed user directory provisioned through SCIM 2.0.
Pocket ID v2.14.0 is the first tested client. Users and groups live in an embedded
SQLite database using `modernc.org/sqlite`; Epithet does not require CGO. Host
inventory remains independent: static YAML and optional file-backed enrollment.

`pkg/directory` owns the storage and administration contracts.
`pkg/directory/scim` adapts Elimity for provisioning.
Elimity supplies the schemas, validation, HTTP routing, pagination, and response
formatting; Epithet supplies authentication and its identity/membership rules.
`pkg/directory` exposes only user facts,
lookup, and snapshot revisions to authorization consumers. The SQLite backend
implements the SCIM storage contract in `pkg/directory/sqlitestore`.

## Configure

Add these settings to a combined-server configuration:

```yaml
inventory:
  directory-source: scim
  # state-dir: /custom/state  # Optional shared storage root override.
  scim-token: REPLACE_WITH_YOUR_PROVISIONING_TOKEN
  # Alternatively, omit scim-token and use:
  # scim-token-file: /etc/epithet/scim.token
  static:
    - /etc/epithet/hosts.yaml
  admin-user:
    - YOUR_POCKET_ID_USER_ID
  oidc:
    issuer: https://identity.example.com
    client-id: YOUR_EPITHET_OIDC_CLIENT_ID
    identity-mode: stable-id
```

Keep your existing `server` and `policy` settings. Supply the provisioning bearer
secret either literally as `inventory.scim-token` or in a file named by
`inventory.scim-token-file`; configuring both is an error in SCIM mode. The service
reads it at startup; change the configured value or secret file and restart to
rotate it, then update Pocket ID. Use TLS at the public reverse proxy as for
certificate issuance. See the [annotated standalone service configuration](../examples/inventory-scim.example.yaml)
for the mapping from CLI flags to YAML.

Configure Pocket ID's SCIM provider for the Epithet OIDC client with endpoint
`https://ca.example.com/scim/v2` and that bearer secret. The combined router forwards
`/scim/v2/…` to inventory. In separate deployments, expose that path on the inventory
listener. Keep the private resolver endpoint restricted to CA-authenticated calls.
Inventory's human management endpoint is `/manage` standalone or `/inventory` on
the combined router; standalone CA must advertise its public management URL via
`ca.inventory-public-url`.

At least one static inventory file is still required for host/domain configuration;
it may contain `hosts: []`. In SCIM mode, static user records are ignored. Configure
an administrator's provider ID, let Pocket ID provision that user, and authenticate
normally with the Epithet agent before running management commands. Alternatively,
`inventory.admin-group` grants administration through a bound policy group name.
The administrator must exist and be active in the selected directory.

The service does not use an agent profile or socket. The `agent.name` setting
below concerns commands run on an administrator's client machine only.

`inventory.state-dir` is the shared storage root. SCIM uses
`directory/directory.db` underneath it; managed host inventory uses `inventory/`.
The root defaults to Epithet's native system state directory:

| Platform | System state directory |
| --- | --- |
| Linux | `/var/lib/epithet` |
| FreeBSD and other BSDs | `/var/db/epithet` |
| macOS | `/Library/Application Support/Epithet` |
| Solaris, illumos, AIX | `/var/opt/epithet` |
| Windows | `%ProgramData%\Epithet` |

Set `inventory.inventory-source: managed` to enable managed host enrollment;
the default is `static`. Storage path settings only override locations and do not
enable either source. Existing managed-host configurations must add
`inventory-source: managed`; `state-dir` alone no longer enables enrollment.
Static sources do not open their corresponding managed stores.

`epithet --config server.yaml inventory --check` validates configuration and opens
(or initializes) the managed directory. The database's parent directory is created
with mode 0700 and a new database with mode 0600. Keep it on local storage. Back up
with a SQLite-aware snapshot, or stop inventory before copying the database;
copying only the main file while WAL writes are active is not a complete backup.

## Identity and lifecycle

Pocket ID's OIDC `sub` is the SCIM user's `externalId`. Both are Epithet's normalized
`id`, including Writ `id:` rules, administrator user grants, and issuance audit.
The distinct, server-generated SCIM `id` is only a provisioning resource identifier
and group membership reference. No username or email fallback exists.

Users require a nonempty, unique `externalId` and `userName`. Usernames are unique
under Unicode normalization and case folding; authentication IDs remain byte exact.
Trusted provisioning can change `externalId`: the same transaction removes the old
identity mapping and establishes the new mapping, preserving the resource's group
memberships. `userName` remains mutable and readable. Stored user attributes are
limited to identity, active status, `userType`, and enterprise
`department`/`organization`. Groups store their provider identity, display name,
and direct member IDs; bound group names join the user attributes in authorization
facts. SQLite stores users, groups, and memberships in separate tables.

- `active: false` retains the user and memberships but prevents new certificates
  under Writ and prevents inventory administration. Omitted `active` defaults to true.
- `DELETE /Users/{id}` deletes the resource and its membership references. Recreating
  the same `externalId` produces a new SCIM ID and requires membership provisioning
  again. An explicit Writ `id:` grant still refers to that provider identity.
- These changes affect subsequent requests. Already issued SSH certificates remain
  valid until expiry; SCIM is not a certificate revocation mechanism.

Pocket ID withdraws resources outside the OIDC client's assigned groups. Removing
and restoring an assignment can therefore delete and recreate users and groups.
Its synchronization compares modification timestamps; provisioning is asynchronous.

Directory administration uses `epithet directory`; `epithet inventory` management
commands operate on hosts. Both use the same service and agent authentication. Management commands inherit
`agent.name` from the loaded configuration, falling back to `default`. For example,
`agent: {name: work}` selects `~/.epithet/run/work/broker.sock` for both commands.
An explicit management `--name` (or command-scoped `name` setting) overrides that
profile; `--broker` overrides the socket path. Configuration comes from the usual
`/etc/epithet/*.{yaml,yml,json}` and `~/.epithet/*.{yaml,yml,json}` files, or the
explicit `--config` path.

## Stable policy group names

A group's initial `displayName` automatically claims its policy name. The name is
bound to that SCIM group ID, so renaming the group preserves the original policy
name. Writ only sees the bound names and knows nothing about SCIM.

A duplicate name is accepted for provisioning, including its membership, but the
new group receives no policy name. It appears as a conflict in the binding list
and audit. Its members do not join the group that already owns the name. Deleting
a bound group reserves its policy name against automatic reuse. This reservation
is a group binding record, not a retained user record.

```sh
epithet directory groups list
epithet directory groups list --json
epithet directory groups bind 'operations' SCIM_GROUP_ID --revision 42
epithet directory groups audit
epithet directory groups audit --after 100 --limit 100
```

Audit output is a page of events in sequence order (100 by default, at most 1000).
Pass the last event's `sequence` as `--after` to continue; an empty page means you
have reached the end. The cursor is an event sequence, not a directory revision:
a single mutation can generate several audit events. Audit history is retained.

List output is tab-separated with directory revision, full group ID, binding
status, policy name, and current display name. Names with control characters or
backslashes are quoted and escaped. The JSON form includes the revision
when the list is empty. Status is `bound`, `conflict`, `unbound`, or `deleted`.

`bind` assigns a free name to an unbound group or explicitly transfers an occupied
or reserved name to that group. Each group has one policy name. Review the source
and target before binding: this changes which members match existing Writ rules
and administrator group grants. The supplied directory revision must still be
current, otherwise the operation fails without changes. Audit records include the
administrator's provider ID and previous/new group IDs. Provisioning bearer tokens
cannot perform this action; the command uses the existing OIDC agent session.
Richer inspection, remediation, and bulk management are deferred.

## Supported protocol

The base path is `/scim/v2`. All endpoints require the provisioning bearer token.

- Users and Groups: GET collection/resource, POST collection, PUT resource, DELETE
  resource. PUT replaces writable attributes rather than merging them.
- Paginated list responses use `startIndex` (one-based) and `count` (maximum 1000).
  `count=0` reports the total without resources. Elimity reports the requested page
  size in `itemsPerPage`, including when fewer resources are returned. Lists have
  deterministic ID order.
- Server-owned IDs, timestamps, versions, and locations; ETag/If-Match conditional
  replace/delete. Stale preconditions return 412 without changing state. Elimity
  currently advertises `etag.supported: false` despite honoring these preconditions.
- Discovery: ServiceProviderConfig, ResourceTypes, and Schemas. The supported profile
  includes user identity, active status, user type, enterprise department/organization,
  and group identity, display name, and direct User member IDs. Names, email addresses,
  other unused profile fields, and unregistered extensions are discarded. The
  schemas describe this subset; password remains recognized solely to reject
  provisioning, and is never stored.
- PATCH, filters, sorting, bulk operations, password changes, nested groups, and
  attribute-selection query parameters are unsupported. Discovery advertises the
  corresponding optional capabilities as unsupported. Okta compatibility is deferred.

Invalid membership references fail the whole operation. Duplicate usernames or user
external IDs return 409. Duplicate group names succeed with an unbound conflict as
explained above. A lost create response can be recovered by listing and correlating
`externalId`, as Pocket ID does; clients should reconcile before retrying group creates.

Each mutation commits resources, identity and membership indexes, policy bindings,
audit, and directory revision atomically. Reads return user facts and their revision
from one database snapshot. Storage failures fail the request; there is no stale
cache or fallback directory. The CA still calls inventory and then policy; neither
Writ nor policy handlers access SQLite or a provisioning API.

## Explicit static recovery

To recover through a configuration-owned account, set `inventory.directory-source`
to `static`, provide that account in static YAML with its verified provider identity,
and restart. Static mode does not open the managed database or provisioning token
file. It disables SCIM and directory-binding management. Host management still
operates if `inventory.inventory-source: managed` is selected. OIDC remains required; this does
not provide access during an identity-provider outage.

Return to `scim` and restart to use managed identities again. There is never an
implicit merge of static and provisioned users. Group reservations and audit survive
restarts in the database. Changing the configured OIDC provider also requires
reconciling the directory's external identities; IDs are scoped to that provider.
