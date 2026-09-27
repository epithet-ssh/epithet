# Directory and inventory services

`epithet directory` serves user facts from static YAML or SCIM-managed SQLite.
`epithet inventory` serves host facts from static YAML and optional file-backed
managed enrollment. CA owns OIDC authentication and evaluates Writ in-process.
The separate `epithet control` service handles human administration, SCIM, and
enrollment. Backends own persistence, mutation invariants, and audit.

## Combined deployment

Provision two distinct signing keys, configured below. Control's key is persistent;
the launcher never generates credentials automatically.

```yaml
server:
  ca-key: /etc/epithet/ca.key
  control-key: /etc/epithet/control.key
  listen: '127.0.0.1:8080'
ca:
  policy-file: /etc/epithet/policy.writ
  oidc:
    issuer: https://identity.example.com
    client-id: epithet
    identity-mode: stable-id
directory:
  source: static
  static: [/etc/epithet/directory-and-hosts.yaml]
inventory:
  static: [/etc/epithet/directory-and-hosts.yaml]
  principal-mode: account-name
control:
  directory-admin-group: [directory-operators]
  inventory-admin-group: [host-operators]
```

Run `epithet --config server.yaml server`. It supervises a router plus four
separate processes: CA, control, directory, and inventory. Each service has a
private Unix socket; the router owns `server.listen`. The launcher supplies public
keys and socket addresses, and copies CA's OIDC settings to control. Static users
and hosts can share a file; each fact service reads its own records. The optional
`server.inventory` override supplies static paths to both services.

With `inventory-source: managed` (the default), `inventory.static` is optional;
omit it when all hosts are managed. Static mode still requires inventory files,
and configured static paths must match files.

The example explicitly selects account-name compatibility. Inventory defaults to
`epithet-principal-v1`; static hosts in that mode need domains, and managed hosts
supply their domain during enrollment. See [principal modes](principals.md).

Keep TLS termination in the existing reverse proxy:

```caddyfile
ca.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

The router sends `/inventory` to control's `/manage`, and `/scim/v2/…` directly
to control. Other routes go to CA. The router adds no credentials. CA advertises
control through `Link: <inventory>; rel="https://epithet.dev/rel/control"`.
The public management operations and response shapes remain unchanged.

## Inspect directory users

```sh
epithet directory users list
epithet directory users list --json
```

These commands use the existing agent session and require an active user with an
`control.directory-admin-user` or `control.directory-admin-group` grant. They list the selected
user directory, independently of host inventory mode. In SCIM mode, static users
are not included. Static-only deployments can configure either administrator grant
to enable inspection without enabling managed host storage.

Default output is one tab-separated row per user with `USERNAME`, `ID`, `ACTIVE`,
and `GROUPS` columns, ordered by username then ID. Inactive users are included.
`ID` is the authentication and policy identity, not a SCIM resource ID. Groups are
sorted, comma-separated policy names; control characters and backslashes in
columns are quoted and escaped. Use JSON to preserve group-name boundaries exactly.

`--json` returns an object containing an opaque `revision` and a `users` array,
including `userName`, `id`, `active`, `groups`, and any configured `userType`,
`department`, and `organization`. Empty directories return `users: []`. Users,
memberships, and revision are read from one snapshot. As with other management
commands, the agent must also be updated to understand the new response.

## Multiple DNS names

An exact host record can grant several equivalent names:

```yaml
hosts:
  - names: [freki.home, freki.tailca597.ts.net]
    labels: {role: server}
    accounts: [brianm]
```

Both names resolve to the same host. Use `names: [freki.home]` for a single name.
Use either `names` or `pattern`. Empty lists, empty
names, repeated names after ASCII case folding, and names claimed by another
record are rejected. Exact names take precedence over patterns.

Writ matches any registered name, including for denies; negation is applied
after matching the whole list. Changing the requested DNS name cannot evade
a deny on that host. This applies regardless of the host's **principal domain**.
Principal domains are opaque issuance metadata, independent of host names and
DNS domains; they never replace the host's names in Writ.

Inventory resolution version 2 and policy API 8 carry `names` arrays in host
facts, replacing `name`. Upgrade the private services and CA together. The
top-level `target` remains the actual requested DNS name.

## Separate deployment

Run `epithet ca`, `epithet control`, `epithet directory`, and `epithet inventory`
under your supervisor. TCP listeners accept HTTP behind TLS termination; each also
accepts `unix:///path/to/socket`. The combined launcher is optional.

- CA: configure `key`, `policy-file`, `directory`, `inventory`, `oidc`, and the
  client-accessible `control-public-url` (normally an HTTPS URL ending `/manage`).
- Control: configure its distinct `key`, `oidc`, `directory` fact-service root,
  role grants, and optional `directory-backend` / `inventory-backend` roots.
  Only built-in providers need these administrative backend URLs.
- Directory: configure `source`, `static` or `state-dir`, `ca-pubkey`, and
  `control-pubkey` if control needs access.
- Inventory: configure `static`, `inventory-source`, `state-dir`, `ca-pubkey`,
  and `control-pubkey` for administration.

Use the same issuer, client ID, and identity mapping on CA and control. Public
keys can be SSH literals, files, or URLs. Fact-service root URLs may include a
path prefix; the client appends `/lookup` and signs the complete query. Keep
private services off the public management route. For an optional standalone
router, use `--ca unix:///path/ca.sock --control unix:///path/control.sock`.

For example, a bespoke directory plus built-in inventory requires only the
custom directory's lookup API; omit `control.directory-backend`. The control
service then authorizes inventory administrators through directory facts.
See the [fact provider contract](fact-services.md).

## Validation and migration

Validate Writ with `epithet policy --check --policy-file policy.writ`, directory
with `epithet directory --check`, and hosts with `epithet inventory --check`.
Policy validation is an offline command; policy evaluation runs inside CA.
Restart the service that owns changed files. Restart the combined server to
restart all children. Restart agents when changing their discovered login or
control endpoint.

Upgrade the services and clients together for this pre-1.0 refactor:

- Move `policy.policy-file`, `default-expiration`, and `extension` to `ca`.
- Move `inventory.oidc` to `ca.oidc`; separately deployed control needs matching
  `control.oidc`. Environment names are now `EPITHET_OIDC_IDENTITY_MODE` and
  `EPITHET_OIDC_USER_ID_CLAIM`.
- Move `inventory.directory-source` to `directory.source`. Configure directory's
  static paths and state root separately. Existing SQLite storage stays at
  `<state-dir>/directory/directory.db`.
- Move SCIM credentials to `control.scim-token` or `control.scim-token-file`.
- Replace the old shared admin grants with explicit `control.directory-admin-*`
  and `control.inventory-admin-*` grants.
- Configure a persistent distinct control key. Replace `ca.inventory-public-url`
  with `ca.control-public-url`, and router `inventory` with `control`.
- Replace the old combined resolution RPC with the two GET lookup APIs. Providers
  no longer receive OIDC tokens or provide login discovery.

Existing host records remain at `<inventory.state-dir>/inventory/records/`.
New enrollment tokens create empty pending host records. Older token-only records
are not accepted by the new loader; outstanding token records must be replaced
when upgrading. There is no automatic storage migration. Active host records and
SCIM database contents retain their formats.

## Lookup and audit

Each lookup returns an active object or 404 and is never cached. Names include
all aliases; principal domains remain opaque and separate from Writ. Required
`accounts` is null (unrestricted), empty (none), or a restricting list.

Fact revisions are optional opaque logging strings, capped at 256 UTF-8 bytes.
When supplied they appear in private issuance audit as `directoryRevision` and
`inventoryRevision`; they do not affect authorization. Certificate Key ID uses
`userName` when present, otherwise `id`. Control-plane record revisions and the
transactional directory-rebinding authorization check remain enforced.
