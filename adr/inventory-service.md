# Inventory service and policy facts

Status: implemented static phase, September 7, 2026.

## Boundaries

`epithet inventory` owns the user directory and host inventory. They are separate
lookup interfaces (`directory.Directory` and `inventory.Hosts`) hosted by one
service. Static YAML loading implements both today. Policy owns compiled Writ,
not files, clients, or credentials for inventory. Dynamic storage, SCIM/LDAP,
write administration, and host admission/enrollment remain follow-up work.

The CA is the caller of both private services. It sends the original OIDC token
and requested host to inventory. Inventory validates authentication, maps the ID,
and resolves directory and host records. The CA forwards normalized authentication
and inventory facts plus the connection to policy, without the bearer token.
Policy verifies the CA service request, checks authentication expiry and fact
binding, then evaluates Writ. The CA checks returned identity and principal
parameters against the resolved records and bounds validity by inventory's verified
authentication expiry before signing. Client-supplied inventory facts are ignored.

Both services trust the CA public key. Requests use the existing request-bound
service JWT, with distinct `epithet-inventory` and `epithet-policy` audiences.
Read authority grants no write capability. Policy and inventory never call each
other. No policy-reader bearer credential or new signing key is introduced.

## Identity and configuration

`inventory.oidc` owns issuer, audience, identity mode, and claim selection.
Neither CA nor policy initializes an OIDC validator or caches identity mapping.
Inventory serves authenticated login discovery; the CA forwards its `auth` object
to agents. Restart inventory after changing identity settings; restart agents when
changing their issuer or client configuration. Policy knows only normalized facts,
not provider claims or verification rules. Authentication is intentionally concrete
OIDC support, without a generic authentication framework.

Static users retain explicit `id` and `userName`. Both stable-id and verified-email
semantics are preserved. SCIM-shaped protocol records do not imply a SCIM endpoint.

## Protocol and snapshots

`POST /v1/resolve` accepts `{token, host}`. Hosts use ASCII case folding, shared
with Writ. Version 1 returns `host`, `authentication: {id, expiresAt}`, `resolvedAt`,
`directory: {revision, user}`, and `inventory: {revision, host}`. User records use
SCIM core User/group-reference fields and the enterprise extension. Host facts
separate `resource` from `principal`. This protocol has no Writ Go types.

Each static revision is a SHA-256 digest of the loaded data for that component;
host revision also includes the effective default principal mode. Revisions are
stable across unchanged restarts. User and host snapshots are internally
immutable but there is no promise of a transaction across future independent
sources. `resolvedAt` is a lookup time, not an upstream freshness guarantee.
Dynamic implementations must define freshness and snapshot reads before use.

Missing entities are explicit null records and produce authorization denial.
An invalid user token returns 401; invalid CA service authentication returns 403
and is treated as an infrastructure error by the CA, avoiding browser reauth loops.
Transport, storage, malformed data, and missing metadata are infrastructure
errors and fail closed. Host `accounts` must be present: null is ungrounded, []
permits no accounts, and a list grounds matching. Bodies are bounded to 64 KiB;
HTTP clients have deadlines and do not follow redirects. There is no resolution
cache; responses carry `Cache-Control: no-store`.

The policy response and certificate audit event include policy content ID,
directory revision, and inventory revision. The policy ID hashes the compiled
policy JSON; directory and inventory revisions describe the facts used. Those
values are audit metadata, not certificate fields.

## Deployment

`epithet server` supervises inventory, policy, and CA subprocesses, passes the
CA public key directly to the private services, and wires separate sockets in
a private temporary directory. Startup failure, child exit, or shutdown stops
and reaps every started child. Only CA has a public listener. Same-user processes
are not a strong filesystem boundary around the CA key; separate deployments
can assign different OS permissions and network placement.

Standalone inventory uses `inventory.static`, `inventory.oidc`,
`inventory.ca-pubkey`, and `inventory.principal-mode`. Standalone CA requires
`ca.inventory` in addition to `ca.policy`. Static inventory exposes no enrollment
capability or enrollment link. The one-command combined path is preserved.
