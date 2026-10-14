# Implementing a fact service

A directory or inventory provider only implements one read endpoint. It does not
validate user login tokens, evaluate Writ, or implement Epithet administration.
CA authenticates the user, looks up current facts, evaluates policy locally, and
signs the certificate. Control may also read directory facts to authorize admins.

| Service | Request | Successful response |
|---|---|---|
| Directory | `GET /lookup?id=OPAQUE_ID` | Active user object |
| Inventory | `GET /lookup?host=HOST_NAME` | Active host object |

Configure the **complete fact endpoint URL** for both directory and inventory,
including its path (the built-in HTTP endpoint is `/lookup`). Unix socket URLs
select the built-in `/lookup` path. Use standard URL query encoding, exactly one named query
parameter, and no request body. Directory IDs are opaque. Host lookup names are
ASCII case-folded, with a trailing dot removed. Return `404` for unknown or inactive
records. Authentication errors and service failures must use their own non-200,
non-404 status; they must not masquerade as an absent record.

Send `Cache-Control: no-store` on every lookup response, including errors. CA
performs fresh reads for each issuance attempt, follows no redirects, and has no
application fact cache. A successful response must be a JSON object, not `null`.
The response limit is 64 KiB.

## Directory

The smallest response is:

```json
{"id":"opaque-user-id"}
```

A fuller response is:

```json
{
  "id": "opaque-user-id",
  "userName": "alice",
  "name": ["alice", "alice@example.com"],
  "groups": [{"id":"scim-group-id", "name":["operators"], "attributes":{"externalId":"upstream-id"}}],
  "attributes": {"userType":"employee", "department":"engineering", "organization":"example"},
  "revision": "provider-defined"
}
```

`id` is required and must match the requested ID. All other fields are optional.
Omitted groups mean no memberships; omitted attributes have no value. There is no
`active` field: returning the object asserts that this user is active. CA uses the
ID for policy identity. The `name` collection controls name selectors. `userName` is presentation only,
with ID as the certificate Key ID fallback; reordering names does not change it.
Each group object is matched independently, even when names overlap. Group IDs
are optional; SCIM providers expose their server-issued resource ID.

Additional attributes are flat string values or arrays of strings. Missing, null,
and empty arrays have no values; an empty string is a value. Other types or
non-string array members invalidate the response. The map cannot contain `name`
or `id`, which use the explicit object fields.

## Inventory

```json
{
  "name": ["host.example", "host.internal"],
  "accounts": ["root", "deploy"],
  "attributes": {"env":"production"},
  "principal": {"mode":"epithet-principal-v1", "realm":"fleet-id"},
  "revision": "provider-defined"
}
```

`name`, `accounts`, and `principal` are required. Names contain every equivalent
normalized host name, including the requested name. Writ evaluates the entire
list, including denies. Names must be nonempty and unique. Optional `attributes` default to no additional values. A provider may also
return an optional `id`.

Accounts must be explicit: `null` imposes no inventory restriction, `[]` permits
no accounts, and an array of names restricts issuance to those accounts. Writ
still decides whether access is allowed.

Principal modes are `{"mode":"account-name"}` or
`{"mode":"epithet-principal-v1","realm":"..."}`. The latter requires a valid,
nonempty opaque principal realm. The realm is credential scope, not a hostname
or a policy selector. Do not substitute it into `name`. Multiple hosts can share
a realm intentionally; all then accept the same principal for a given account.

Both response types may include `revision`, an opaque string of at most 256 UTF-8
bytes. It is logged only: no comparison, ordering, caching, or authorization
semantics. Omission needs no replacement. Null, a non-string, or an oversized
revision invalidates the response. This metadata is unrelated to control-plane
mutation revisions.

## Request authentication

Trust the configured CA public key for reads. If control needs reads, configure
its distinct public key as well. Only control's key authorizes private mutation
APIs. These public keys are provisioned out of band; no shared user credential is
sent to a fact provider.

Each request has `Authorization: Bearer JWT`, signed with the calling service's
SSH private key. `pkg/serviceauth` owns signing and verification of these
request-bound credentials. Providers using their own HTTP handlers can use
`serviceauth.NewVerifierFor` with `DirectoryAudience` or `InventoryAudience`;
the built-in handlers configure verification themselves.

`pkg/facts.NewDataClient` configures directory and inventory lookup endpoints and
exposes only validated `User` and `Host` lookups. `NewControlClient` configures
private backend endpoints and exposes typed administration operations. SCIM
forwarding is private to `pkg/facts/control`, alongside its discovery and resource
URL rebasing. The shared `internal/servicehttp` package owns connections, TLS and
Unix sockets, signed exchanges and bounded response reads. It has no knowledge
of fact resources or SCIM, and callers do not manage HTTP response bodies.

`pkg/facts/server` owns built-in service handlers. `DirectoryHandler` and
`InventoryHandler` require a data source and assemble lookup authentication and
routes. Add management explicitly with the corresponding typed option:

```go
directoryHTTP, err := factserver.DirectoryHandler(
    directoryData, caPublicKey, controlPublicKey,
    factserver.WithDirectoryManagement(directoryManagement),
)
inventoryHTTP, err := factserver.InventoryHandler(
    inventoryData, caPublicKey, controlPublicKey,
    factserver.WithInventoryManagement(inventoryManagement),
)
```

The required sources implement `directory.Directory` and `inventory.Hosts`.
The optional management implementations satisfy `directory.Store` and
`inventory.Store`, which do not embed the data interfaces. Each pair must describe
the same logical service, but may use different instances. A store implementing
both can be supplied in both positions. Omitting the option leaves management
disabled even if the source implements Store. Directory's existing read-only
actor and user-list operations remain available; with management configured,
administrative user listing uses that implementation.

`LookupHandler` is the lower-level adapter for serving just fact reads at a
caller-owned route. The CLI owns all source lifetimes, key resolution, and listeners.
`pkg/facts/control` owns public authentication and administrative authorization;
it depends on the typed clients, without importing the built-in handlers or stores.

Human control operations receive the already authorized actor and directory
revision explicitly. SCIM preserves the OIDC actor or uses `scim` for the
optional provisioning secret. Enrollment retains its nonhuman credential semantics. Control results are domain records; rejected operations
return `ServiceError`, with categories available through `errors.Is`. SCIM results
retain the provisioning status, response body, ETag, location, and response format.
`facts.AdminClient` invokes the public administration endpoint using user bearer
credentials. Its requests and responses are also defined in `pkg/facts`.

| Claim | Meaning |
|---|---|
| `iss` | OpenSSH SHA256 fingerprint of the signing key |
| `sub` | Authenticated actor for management; omitted for service-only reads/enrollment |
| `aud` | `epithet-directory` or `epithet-inventory` |
| `iat`, `exp` | Unix seconds; token lifetime is 60 seconds |
| `jti` | Random request identifier |
| `htm` | Exact HTTP method |
| `htu` | HTTP authority plus escaped path and raw query, e.g. `facts.example/lookup?id=a%2Bb` |
| `if_match` | Exact If-Match header value, omitted when empty |
| `content_type` | Exact Content-Type header value, omitted when empty |
| `bh` | Unpadded base64url SHA256 digest of the body; empty-body digest for GET |

Verify signature, audience, expiry and issued-at freshness, method, target including query,
body digest, If-Match, and Content-Type. Algorithms follow the SSH key type: Ed25519 uses EdDSA, RSA
uses PS256, and supported ECDSA curves use ES256/ES384. Preserve authority, escaped
path, and query through proxies. Rewriting any of them invalidates the signature.
Tokens are request-bound but do not use a replay database. TLS remains necessary
for remote services; Unix sockets are supported for local services.

The built-in stores share database permissions and connection settings through
`pkg/facts/storage`. Each store owns its schema, transactions, audit records, and
authorization invariants. The storage package is independent of the fact-service
HTTP handlers and the control plane.

See [inventory-api.yaml](inventory-api.yaml) and
[directory-api.yaml](directory-api.yaml) for response schemas, and
[the inventory package](../pkg/facts/inventory/README.md) for management and deployment configuration. Bespoke providers do not
need Epithet's private `/manage` or `/actor` backend endpoints.

## Package ownership

`pkg/facts` contains the shared directory and inventory protocol types, clients,
and service authentication. Its consumers do not link built-in stores or handlers.
The fact-service implementation lives under the same namespace:

| Package | Responsibility |
|---|---|
| `facts/control` | Public authentication and administrative authorization |
| `facts/server` | Built-in lookup and private management HTTP handlers |
| `facts/directory` | Directory contracts and static YAML user loading |
| `facts/directory/sqlitestore` | Managed directory persistence and invariants |
| `facts/directory/scim` | SCIM protocol adaptation to the directory contract |
| `facts/inventory` | Host lookup and managed store contracts, records, and proposal validation |
| `facts/inventory/sqlitestore` | Managed inventory persistence and admission invariants |
| `facts/storage` | Shared SQLite permissions and connection settings |

Directory and inventory contracts stay independent of their SQLite implementations,
allowing alternative managed stores. `directory.Store` and `inventory.Store` expose
complete management operations independently of the data-plane interfaces; each backend owns atomic changes, conflicts, audit history,
and revisions. Every operation carries a request context. Service handlers accept
these contracts and leave store lifetime to their caller. A backend can use an
external database without changing the control plane or fact clients.

The SCIM adapter owns its protocol parsing and response
semantics, separately from store transactions. Combined YAML host loading is
integration-test support in `test/inventorytest`; production inventory is
managed only, and static directory loading supplies user facts only.

Policy evaluation lives separately in `pkg/writpolicy`. CA owns the evaluator
interface it consumes; Writ evaluation uses supplied facts and has no service
transport or storage responsibility.

## Built-in managed storage

The built-in directory and inventory services each own a separate SQLite
database under `state-dir`: `directory/directory.db` for SCIM users and
`inventory/inventory.db` for managed exact and pattern records. Both use private database files,
foreign keys, WAL journaling, and fully synchronous transactions. Static directory
facts remain YAML configuration; the host proposal editor also continues to use YAML.

Managed inventory stores typed host records, names, labels, accounts, enrollment
tokens, and audit events. Mutations check admission rules and commit the host,
token state, audit, and inventory revision together. Lookups read current host
facts and the revision in one snapshot. Pending and denied hosts supply no facts;
exact records take precedence over pattern records. A pattern match exposes the
requested hostname as its resource name. If multiple active patterns match, lookup
fails with a conflict rather than selecting one by order.
Removing a managed host also deletes its names, token metadata, and audit history.

Inventory administration returns bounded pages: 100 records by default, with a
maximum of 1,000. `inventory list` accepts `--after FULL_ID`
and `--limit N`; `inventory list --pending` filters before applying the page limit.
Host pages are selected by ID, then sorted by name for display. A full host page
prints its continuation ID to stderr, preserving the concise stdout table.
Use the continuation ID rather than the last displayed name. Tokens have no
retrieval operation; create returns a credential and revoke takes that credential.

`inventory audit --after SEQUENCE --limit N` uses the same page bounds. Events
include a stable, increasing `sequence`; timestamps do not define pagination.
Sequences are never reused after deletion or restart. The last event's sequence
is the next cursor. An empty page ends enumeration; separate pages may observe
concurrent changes. A full page can be followed by an empty one.

CLI/control requests use `after`, `limit`, and `pending` for host lists,
and `audit-after` and `audit-limit` for inventory or
directory audit. Zero limits select the default; negative or oversized limits
are rejected. Each database query applies its limit before loading the page.

Host inventory has no static mode or file overlay. Each editable proposal contains
either `names` (1–64 exact DNS names) or `pattern`, never both. Patterns use the
same DNS-label matching language as Writ host selectors: `*` and `?` within a
label, and whole-label `**` across labels. The standalone `*` matches any hostname.

Existing `inventory/records/*.yaml` files are not read or imported by the SQLite
backend. Convert existing managed state with the service stopped before starting
this version. `inventory --check` initializes and validates the configured
database; schema or storage errors fail startup. The old `inventory-mode`,
`inventory-static-file`, and server-wide `principal-mode` settings are removed.
Principal mode is explicit on each managed record.

Use `epithet inventory add-pattern 'ci-*.example'` to declare an active pattern
through the YAML editor. Creation requires inventory-admin authorization. Choose
its labels, explicit accounts (`null`, `[]`, or a list), principal mode, and realm.
Patterns cannot use a generated per-host realm. Existing `edit`, `show`, and
`remove` commands operate on pattern records by ID or their pattern text. Pattern
creation, editing, and removal update the inventory revision transactionally.

Named realms need no separate declaration. They are case-sensitive attributes
of records, and may include uppercase ASCII letters. All active records sharing
the same named realm must have identical labels and account sets; account order
does not matter, while `null` and `[]` remain distinct.

The built-in directory's [mapping and database upgrade procedure](../pkg/facts/directory/README.md)
explain current SCIM group names, optional static group IDs, and removal of historical bindings.

## Optional inventory management

Control discovers inventory management through OPTIONS and Link-Template at the
configured inventory fact endpoint. A 4xx discovery response means a lookup-only
provider. See the [inventory provider contract](../pkg/facts/inventory/README.md)
for resources, JSON, preconditions, automation credentials and backend integration.
The inventory provider no longer exposes the private `/manage` action envelope.

## Optional SCIM management

Control sends signed OPTIONS to the configured directory fact endpoint. A managed
provider advertises its SCIM base URI with an ordinary RFC 8288 Link:

```http
HTTP/1.1 204 No Content
Allow: GET, OPTIONS
Cache-Control: no-store
Link: </scim/v2/>; rel="https://epithet.dev/rel/scim"
```

The target can be absolute or relative to the fact URL; it must have no query,
fragment or credentials. Unix services advertise same-service references. Any
initial OPTIONS 4xx means data-only support; successful OPTIONS without this
relation has the same meaning. Transport failures, redirects, 5xx, and invalid
advertised URLs are errors. Discovery is refreshed per operation. Operation-level
4xx responses retain their SCIM meaning and never trigger discovery fallback.

SCIM already defines resource paths and query parameters, so its base uses Link,
not Link-Template. Control appends the requested SCIM resource path and preserves
the method, escaped path, raw query, body, Content-Type and If-Match in a direct
signed HTTP request. The old POST `/scim` JSON tunnel is removed. The public
endpoint remains `/scim/v2/`; statuses, ETags and SCIM errors pass through.
Location headers and standard `meta.location`, User `groups.$ref`, and Group
`members.$ref` within the provider's advertised SCIM tree are rebased to public
`/scim/v2/` references, including ListResponse resources. External references and
extension attributes are preserved.

Public requests may authenticate with the optional `scim-token`/`scim-token-file`
secret or OIDC. OIDC requires an active directory user with `directory-admin`
grants; inventory grants and the inventory automation secret do not confer this
access. With no SCIM secret, OIDC access remains available. The provider trusts
only control signatures, which cover the actor, method, target, body, Content-Type
and If-Match. User bearer tokens never reach the provider. Mutations record the
human actor in audit, or `scim` for the provisioning secret.

SCIM discovery uses `directory`, the complete fact endpoint URL. The optional
`directory-backend` remains the built-in service root for existing actor snapshots,
user/group listings and audit commands; it is not required by external SCIM
providers. The built-in adapter keeps its current supported SCIM subset, schema
and storage. Directory CLI creation/editing remains deferred in YATL `ywxp1g89`.

**Configuration change:** HTTP directory URLs now name the complete lookup path,
just like inventory URLs. Add `/lookup` to existing built-in HTTP directory root
URLs on CA and control. Unix socket configuration is unchanged. Update signed
request implementations together to bind `content_type` as well as `if_match`.

