# Inventory service

`epithet inventory` serves the user directory and host inventory used during
certificate issuance. It also verifies OIDC tokens and maps them to directory IDs. Static YAML can be combined with file-backed dynamic host enrollment and
administration. See [dynamic inventory](dynamic-inventory.md) for configuration,
commands, and the first implementation decisions. SCIM and LDAP remain later work.

## Combined deployment

```yaml
server:
  ca-key: /etc/epithet/ca.key
  listen: '127.0.0.1:8080'
policy:
  policy-file: /etc/epithet/policy.writ
inventory:
  oidc:
    issuer: https://accounts.google.com
    client-id: your-client-id
    identity-mode: stable-id
  static:
    - /etc/epithet/inventory.yaml
  principal-mode: account-name
```

Run `epithet --config server.yaml server`. It starts and supervises a plain HTTP
router plus CA, inventory, and policy. All three services listen on separate
Unix sockets in a private temporary directory; the router owns `server.listen`.
CA public-key configuration and private socket addresses are supplied
automatically. OIDC is configured only on inventory; all user IDs
belong to that configured provider. Select principal mode deliberately; see
[principal modes](principals.md).

Keep TLS termination and ACME in Caddy (or your existing front end). For the
loopback listener above, a Caddy site can forward all requests unchanged:

```caddyfile
ca.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Clients use `https://ca.example.com/`. Caddy forwards HTTP to the router; Epithet
does not manage HTTPS certificates. Existing Caddy configurations that forward
to the same `server.listen` address need no routing changes.

The router forwards `/inventory` to inventory's `/manage` endpoint when
`inventory.state-dir` is configured. Other paths go to the CA, including `/`
and `/discovery`. Policy and inventory resolution remain private. The router
adds no service credentials and makes no authentication or authorization
decisions. The CA advertises the relative inventory link but does not proxy
inventory management requests. There is no `ca.inventory-proxy` setting.

`epithet router` can also be run separately with `--ca unix:///path/ca.sock` and
optional `--inventory unix:///path/inventory.sock`. Standalone `epithet ca` and
`epithet inventory` retain their TCP and Unix listener options.

Inventory uses the configured URL as its complete RPC endpoint: POST resolves
`{token, host}`, and GET returns login discovery. No path suffix is appended.
For example, `https://inventory.example.com/internal/inventory` receives both
methods at `/internal/inventory`. Reverse proxies must preserve the Host header
and path because the service JWT binds both. Query parameters are not supported.
Unix socket endpoints use `/` for both methods. Resolution responses retain
the `version` field as the protocol-version mechanism.

The existing YAML record format is unchanged: top-level `users`, `hosts`, and
`domains`, with explicit user `id` and `userName`. Files may contain users, hosts,
or both. Paths/globs concatenate in order; duplicates and unknown fields are
errors. See [user and host records](policy-server.md#inventory).

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
a deny on that host. A shared **principal domain** still exposes only the domain
to Writ, preserving its authorization boundary. Principal domains and DNS
domains are separate concepts.

Inventory resolution version 2 and policy API 8 carry `names` arrays in host
facts, replacing `name`. Upgrade the private services and CA together. The
top-level `target` remains the actual requested DNS name.

## Separate deployment

Inventory accepts a literal CA public key, a key file, or an HTTPS key URL:

```sh
epithet inventory --static /etc/epithet/inventory.yaml \
  --oidc-issuer https://accounts.google.com --oidc-client-id your-client-id \
  --ca-pubkey /etc/epithet/ca.pub --listen 127.0.0.1:9998
```

Run policy with its Writ file and CA public key. Configure
CA with both `--policy https://policy.example.com` and
`--inventory https://inventory.example.com`. TCP listeners serve HTTP; provide
TLS at your reverse proxy for remote deployment. Unix socket URLs are supported
for local deployment. Plain HTTP clients require explicit `--insecure`.

Only the CA can resolve inventory or ask policy for decisions. Both services
verify request-bound JWTs against its public key, using different service
audiences. No separate policy-to-inventory credential is needed. The static
service has no write or enrollment routes. Configuring `inventory.state-dir` adds
the separately authenticated `/manage` endpoint.

## Validation and migration

Move `policy.inventory` to `inventory.static`, and `policy.principal-mode` to
`inventory.principal-mode`. Move the entire `policy.oidc` block to
`inventory.oidc`, including issuer, client ID/secret, identity mode, and claim
override. There is no separate top-level `inventory.issuer`. Standalone CA also
needs `ca.inventory`. The corresponding environment variables are now
`EPITHET_INVENTORY_OIDC_IDENTITY_MODE` and `EPITHET_INVENTORY_OIDC_USER_ID_CLAIM`.

```sh
epithet --config server.yaml policy --check
epithet --config server.yaml inventory --check
```

The checks are independent and offline. Policy checks compilation, plugin
references, and rule syntax; inventory checks files, principal configuration,
and identity-mode syntax. Neither needs a CA key or a reachable OIDC provider to check.

`epithet server --inventory PATH` remains a convenient file override; it now
forwards to the inventory subprocess. `server --principal-mode` overrides the
inventory default. `epithet policy --inventory` and `policy --principal-mode`
are removed.

Restart inventory after editing its files; restart policy after editing Writ.
Restart inventory when changing OIDC identity mapping. Restart agents if changing
the login issuer or client settings they discovered at startup. Combined deployments can restart `epithet server`.
Inventory lookup now uses POST at the configured endpoint instead of appending
`/v1/resolve`. Update proxy routes to send both GET and POST to inventory at
that endpoint, preserving the signed host and path, and upgrade CA and inventory
together.

Upgrade these services together: older policy requests do not carry the required
facts. Inventory responses now use top-level `target` instead of `host`;
CA and inventory must be upgraded together for this rename. The lookup request
still uses `{token, host}`. Host responses are also flattened: move the old
`inventory.host.resource` fields (`name`, `labels`, `accounts`) directly into
`inventory.host`, alongside `principal`. CA still forwards only the policy fields.

User responses no longer carry SCIM schema URIs: remove `schemas`, replace
group objects with membership strings, and move `department` and `organization`
directly into `directory.user`. The same user shape is projected to policy.
Static user YAML and user matching semantics are unchanged.

Policy API 8 uses projected policy facts and authorization
limits; see [custom policy migration](policy-server.md#custom-policy-migration-api-8).
Client and agent identity output are unchanged by the extraction.

## Resolution and audit

The [v2 API](inventory-api.yaml) returns separate directory and inventory
snapshots with content revisions, the requested connection `target`, the normalized
authenticated `id`, and an `expiresAt` bound. `target` must match the request
`host`; `inventory.host.names` lists the equivalent host names and may instead contain only
a shared domain. Inventory never returns the bearer token. CA validates the
full resolution, retains both revisions and principal metadata,
and sends only authentication, requested target, user, and host resource fields to
policy with the connection. Policy has no OIDC configuration or inventory envelope.
Inventory also serves authenticated `GET /` login discovery, which the CA exposes
anonymously to agents. A missing user or host denies access; an
unavailable or malformed service fails issuance as an infrastructure error.
`accounts: null` means ungrounded, `accounts: []` permits no accounts, and a list
limits the available accounts. The wire field cannot be omitted.

Certificate issuance logs include `id`, `userName`, `policyId`,
`directoryRevision`, and `inventoryRevision`. Certificate Key ID remains
`userName`. Revisions identify the loaded facts and stay in CA's private audit records;
policy neither receives nor echoes them. The unused `resolvedAt` field has been
removed. Managed reads use committed snapshots and content revisions; writes become
visible to subsequent reads immediately. No resolver cache is used.

The [architecture decision](../adr/inventory-service.md) explains the trust and
component boundaries.
