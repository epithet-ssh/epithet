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

For provider-specific research on aligning login identities with provisioned
users, see [Mapping OIDC identities to SCIM users](oidc-scim-identity-mapping.md).

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
  "principal": {"mode":"epithet-principal-v1", "realm":"fleet-id"}
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

Directory responses may include `revision`, an opaque string of at most 256 UTF-8
bytes. It is logged only: no comparison, ordering, caching, or authorization
semantics. Omission needs no replacement. Null, a non-string, or an oversized
revision invalidates the response. This metadata is unrelated to control-plane
mutation revisions. The built-in directory lookup does not produce a revision.

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
exposes only validated `User` and `Host` lookups. `pkg/facts/control` owns private
provider operations alongside public authentication and authorization. Its directory,
inventory, and SCIM adapters keep provider discovery, protocol conversion, and
resource URL rebasing inside control. The shared `internal/servicehttp` package owns connections, TLS and
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
disabled even if the source implements Store. Directory's read-only actor
operation remains available. User enumeration uses
the SCIM API and requires a provider with SCIM management support.

Use the same constructors without a management option for lookup-only services.
The lookup adapter is private to `pkg/facts/server`. The CLI owns all source
lifetimes, key resolution, and listeners. Control does not import the built-in
handlers or stores. Inventory REST conversion belongs to the HTTP adapter;
the inventory domain has no dependency on the administration protocol.

Human control operations receive the already authorized actor explicitly. SCIM
preserves the OIDC actor or uses `scim` for the optional provisioning secret. Enrollment retains its nonhuman credential semantics. Control results are domain records; rejected operations
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
complete management operations independently of the data-plane interfaces.
Directory consistency, concurrency and propagation semantics belong to each backend;
the directory contract does not require transactions or coherent snapshots.
Inventory retains its operation-specific atomicity requirements. Every operation
carries a request context. Service handlers accept these contracts and leave store
lifetime to their caller. A backend can use an
external database without changing the control plane or fact clients.

The SCIM adapter owns its protocol parsing and response
semantics, separately from backend persistence. Combined YAML host loading is
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
token state and audit together. Lookups return current host facts without an
inventory-wide revision. Pending and denied hosts supply no facts;
exact records take precedence over pattern records. A pattern match exposes the
requested hostname as its resource name. If multiple active patterns match, lookup
fails with a conflict rather than selecting one by order.
Removing a managed host deletes its names and token metadata, retains audit history,
and appends the supplied removal event.

Inventory administration returns bounded pages: 100 records by default, with a
maximum of 1,000. `inventory list` accepts `--after FULL_ID`
and `--limit N`; `inventory list --pending` filters before applying the page limit.
Host pages are selected by ID, then sorted by name for display. A full host page
prints its continuation ID to stderr, preserving the concise stdout table.
Use the continuation ID rather than the last displayed name. Tokens have no
retrieval operation; create returns a credential and revoke takes that credential.

`inventory audit --cursor CURSOR --limit N` uses the same page bounds. Audit
pages contain `events` and an optional `next` cursor. Events retain their supplied
timestamps and have no sequence field. Pass `next` back unchanged; its format is
owned by the backend. Empty `next` ends enumeration. Ordering, consistency during
writes, and cursor lifetime are backend properties.

CLI/control requests use `after`, `limit`, and `pending` for host lists,
and `audit-cursor` and `audit-limit` for inventory or directory audit. Zero limits
select the default; negative or oversized limits are rejected. Audit pagination
does not require global ordering or unique timestamps.

Host inventory has no static mode or file overlay. Each host contains
`names` (1–64 exact hostnames or wildcard expressions). Wildcard names use the
same DNS-label matching language as Writ host selectors: `*` and `?` within a
label, and whole-label `**` across labels. The standalone `*` matches any hostname.

Existing `inventory/records/*.yaml` files are not read or imported by the SQLite
backend. Convert existing managed state with the service stopped before starting
this version. `inventory --check` initializes and validates the configured
database; schema or storage errors fail startup. The old `inventory-mode`,
`inventory-static-file`, and server-wide `principal-mode` settings are removed.
Principal mode is explicit on each managed record.

Use `epithet inventory add 'ci-*.example'` to declare an active host with a wildcard name
through the YAML editor. Creation requires inventory-admin authorization. Choose
its labels, explicit accounts (`null`, `[]`, or a list), principal mode, and realm.
Existing `edit`, `show`, and
`remove` commands operate on the same host records by ID or name, including wildcard
names. Creation, editing, and removal record their supplied audit events.

Named realms need no separate declaration. They are case-sensitive attributes
of records, and may include uppercase ASCII letters. Any realm, including a
generated realm, may be shared by exact hosts or patterns. Each record retains
its own labels and account restrictions; sharing a realm imposes no equality or
uniqueness constraint.

The built-in directory's [mapping and database upgrade procedure](../pkg/facts/directory/README.md)
explain current SCIM group names, optional static group IDs, and removal of historical bindings.

## Optional inventory management

Control discovers inventory management through OPTIONS and Link-Template at the
configured inventory fact endpoint. A 4xx discovery response means a lookup-only
provider. See the [inventory provider contract](../pkg/facts/inventory/README.md)
for resources, JSON, preconditions, automation credentials and backend integration.
The inventory provider no longer exposes the private `/manage` action envelope.

Pending enrollment requires a shared bearer token configured on control with
`enrollment-token` or `enrollment-token-file`; omitting both disables pending
submissions. `epithet host enroll --enrollment-token-file FILE` sends the credential
to control, which accepts it only for pending enrollment and never forwards it to
the inventory provider. Administrator approval remains necessary. Single-use
preapproval tokens remain a separate enrollment path.

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

SCIM discovery uses `inmemoryInventory`, the complete fact endpoint URL. The optional
`directory-backend` remains the built-in service root for existing actor snapshots
and audit commands; it is not required by external SCIM
providers. The built-in adapter keeps its current supported SCIM subset, schema
and storage. Directory CLI creation/editing remains deferred in YATL `ywxp1g89`.

**Configuration change:** HTTP directory URLs now name the complete lookup path,
just like inventory URLs. Add `/lookup` to existing built-in HTTP directory root
URLs on CA and control. Unix socket configuration is unchanged. Update signed
request implementations together to bind `content_type` as well as `if_match`.


### Listing users and groups through control

`epithet directory users list` and `epithet directory groups list` use the agent's
OIDC session to request `GET /scim/v2/Users` or `GET /scim/v2/Groups` on control
with `startIndex=1&count=100`, then consume each page before requesting the next
offset. Control discovers and forwards to the provider's SCIM API. Lookup-only
directories do not support enumeration. The built-in adapter uses `ListUsers`
and `ListGroups`; storage has no separate group summary or snapshot operation.

The user table shows `USERNAME`, SCIM resource `ID`, `EXTERNAL_ID`, and `ACTIVE`.
The group table shows `ID` and `NAME`, with no directory revision column.
`--json` emits one complete SCIM resource per line, including provider extensions.
Groups include their complete membership lists; the built-in SCIM user
representation does not include group memberships. Pagination bounds the number
of groups per page, not the members of an individual group. Client response-size
limits still apply.

Pagination describes each page's current state; concurrent changes can affect an
offset-based enumeration. If a later page fails, earlier output remains visible
and the command exits unsuccessfully.
