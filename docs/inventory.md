# Directory and inventory services

`epithet directory` serves user facts from static YAML or SCIM-managed SQLite.
`epithet inventory` serves host facts from static YAML and optional file-backed
managed enrollment. CA owns OIDC authentication and evaluates Writ in-process.
The separate `epithet control` service handles human administration, SCIM, and
enrollment. Backends own persistence, mutation invariants, and audit.

## Combined deployment

Provision two distinct signing keys, configured below. Control's key is persistent;
the launcher never generates credentials automatically.

```toml
ca-key-file = "/etc/epithet/ca.key"
control-key-file = "/etc/epithet/control.key"
directory-admin-group = ["directory-operators"]
directory-mode = "static"
directory-static-file = ["/etc/epithet/directory-and-hosts.yaml"]
inventory-admin-group = ["host-operators"]
inventory-static-file = ["/etc/epithet/directory-and-hosts.yaml"]
listen = "127.0.0.1:8080"
oidc-client-id = "epithet"
oidc-identity-mode = "stable-id"
oidc-issuer = "https://identity.example.com"
policy-file = "/etc/epithet/policy.writ"
principal-mode = "account-name"
```

Run `epithet --config server.toml server`. It supervises a router plus four
separate processes: CA, control, directory, and inventory. Each service has a
private Unix socket; the router owns `listen`. The launcher supplies public
keys and socket addresses, and copies CA's OIDC settings to control. Static users
and hosts can share a file; each fact service reads its own records. The optional
`directory-static-file` and `inventory-static-file` overrides supply
paths to their respective services. To share a file, supply it to both options.

With `inventory-mode = "enrollment"` (the default), `inventory-static-file` is optional;
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
`directory-admin-user` or `directory-admin-group` grant. They list the selected
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

- CA: configure `ca-key-file`, `policy-file`, `directory`, `inventory`, `oidc-*`, and the
  client-accessible `control-public` (normally an HTTPS URL ending `/manage`).
- Control: configure its distinct `control-key-file`, `oidc-*`, `directory` fact-service root,
  role grants, and optional `directory-backend` / `inventory-backend` roots.
  Only built-in providers need these administrative backend URLs.
- Directory: configure `directory-mode`, `directory-static-file` or `state-dir`,
  `ca-public-key`, and `control-public-key` if control needs access.
- Inventory: configure `inventory-static-file`, `inventory-mode`, `state-dir`,
  `ca-public-key`, and `control-public-key` for administration.

Use the same issuer, client ID, and identity mapping on CA and control. Public
keys can be SSH literals, files, or URLs. Fact-service root URLs may include a
path prefix; the client appends `/lookup` and signs the complete query. Keep
private services off the public management route. The combined `server` launcher
supplies private router endpoints internally; separately deployed services use
the deployment's reverse proxy.

For example, a bespoke directory plus built-in inventory requires only the
custom directory's lookup API; omit `directory-backend`. The control
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

- Service configuration is flat TOML, using exact long flag names as keys.
  Lists use arrays. Static user and host data remain YAML.
- CA uses `policy-file`, `certificate-default-ttl`, and `certificate-extension`.
- Configure `oidc-issuer`, `oidc-client-id`, and the identity settings on CA and
  separately deployed control. Existing environment names remain
  `EPITHET_OIDC_IDENTITY_MODE` and `EPITHET_OIDC_USER_ID_CLAIM`.
- Select `directory-mode` and `inventory-mode` independently. SQLite storage
  stays at `<state-dir>/directory/directory.db`.
- Control uses `scim-token` or `scim-token-file`, plus explicit
  `directory-admin-*` and `inventory-admin-*` grants.
- Configure distinct persistent `ca-key-file` and `control-key-file` values.
  CA advertises management through `control-public`.
- Fact providers expose the two GET lookup APIs; they receive neither OIDC
  tokens nor responsibility for login discovery.

Existing host records remain at `<state-dir>/inventory/records/`.
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
