# Inventory service

`epithet inventory` serves the user directory and host inventory used during
certificate issuance. It also verifies OIDC tokens and maps them to directory IDs. Static YAML is the initial implementation. Dynamic host
enrollment, SCIM, and LDAP are not implemented yet.

## Combined deployment

```yaml
server:
  ca-key: /etc/epithet/ca.key
  listen: ':8080'
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

Run `epithet --config server.yaml server`. It starts and supervises all three
services. CA public-key configuration and the two private Unix socket addresses
are supplied automatically. OIDC is configured only on inventory; all user IDs
belong to that configured provider. Select principal mode deliberately; see
[principal modes](principals.md).

The existing YAML record format is unchanged: top-level `users`, `hosts`, and
`domains`, with explicit user `id` and `userName`. Files may contain users, hosts,
or both. Paths/globs concatenate in order; duplicates and unknown fields are
errors. See [user and host records](policy-server.md#inventory).

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
service has no write or enrollment routes.

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
Upgrade these services together: older policy requests do not carry the required
facts. Client and agent identity output are unchanged by the extraction.

## Resolution and audit

The [v1 API](inventory-api.yaml) returns separate directory and inventory
snapshots with content revisions, the normalized authenticated `id`, and an
`expiresAt` bound. Inventory never returns the bearer token. The CA forwards
these facts and the connection to policy; policy has no OIDC configuration.
Inventory also serves authenticated `GET /` login discovery, which the CA exposes
anonymously to agents. A missing user or host denies access; an
unavailable or malformed service fails issuance as an infrastructure error.
`accounts: null` means ungrounded, `accounts: []` permits no accounts, and a list
limits the available accounts. The wire field cannot be omitted.

Certificate issuance logs include `id`, `userName`, `policyId`,
`directoryRevision`, and `inventoryRevision`. Certificate Key ID remains
`userName`. Revisions identify the loaded facts; the lookup timestamp is not a
guarantee about upstream freshness. No resolver cache is used.

The [architecture decision](../adr/inventory-service.md) explains the trust and
component boundaries.
