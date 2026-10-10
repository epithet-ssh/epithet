# Implementing a fact service

A directory or inventory provider only implements one read endpoint. It does not
validate user login tokens, evaluate Writ, or implement Epithet administration.
CA authenticates the user, looks up current facts, evaluates policy locally, and
signs the certificate. Control may also read directory facts to authorize admins.

| Service | Request | Successful response |
|---|---|---|
| Directory | `GET /lookup?id=OPAQUE_ID` | Active user object |
| Inventory | `GET /lookup?host=HOST_NAME` | Active host object |

Configure each service's root URL on CA. The client appends `/lookup`; a root may
include a path prefix. Use standard URL query encoding, exactly one named query
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
  "groups": ["operators"],
  "userType": "employee",
  "department": "engineering",
  "organization": "example",
  "revision": "provider-defined"
}
```

`id` is required and must match the requested ID. All other fields are optional.
Omitted groups mean no memberships; omitted attributes have no value. There is no
`active` field: returning the object asserts that this user is active. CA uses the
ID for policy identity. A missing username does not match a `userName` selector;
ID is used only as a display/certificate Key ID fallback.

## Inventory

```json
{
  "names": ["host.example", "host.internal"],
  "accounts": ["root", "deploy"],
  "labels": {"env":"production"},
  "principal": {"mode":"epithet-principal-v1", "realm":"fleet-id"},
  "revision": "provider-defined"
}
```

`names`, `accounts`, and `principal` are required. Names contain every equivalent
normalized host name, including the requested name. Writ evaluates the entire
list, including denies. Names must be nonempty and unique. Optional `labels`
default to no labels.

Accounts must be explicit: `null` imposes no inventory restriction, `[]` permits
no accounts, and an array of names restricts issuance to those accounts. Writ
still decides whether access is allowed.

Principal modes are `{"mode":"account-name"}` or
`{"mode":"epithet-principal-v1","realm":"..."}`. The latter requires a valid,
nonempty opaque principal realm. The realm is credential scope, not a hostname
or a policy selector. Do not substitute it into `names`. Multiple hosts can share
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
SSH private key. `pkg/facts` is the reference implementation. Its
`NewDataClient` configures directory and inventory lookup endpoints and exposes
only validated `User` and `Host` lookups. `NewControlClient` configures private
backend endpoints and exposes typed administration and provisioning operations.
Both select service audiences and own their signed HTTP transport internally;
callers do not supply paths or manage HTTP response bodies.

`pkg/facts/server` owns built-in service handlers. `DirectoryHandler` and
`InventoryHandler` assemble lookup authentication, optional private control
operations, and routes. `LookupHandler` serves a read-only directory or inventory
source. The CLI owns store lifetimes, key resolution, and listeners.
`pkg/facts/control` owns public authentication and administrative authorization;
it depends on the typed clients, without importing the built-in handlers or stores.

Human control operations receive the already authorized actor and directory
revision explicitly. Enrollment and SCIM provisioning keep their nonhuman
credential semantics. Control results are domain records; rejected operations
return `ServiceError`, with categories available through `errors.Is`. SCIM results
retain the provisioning status, response body, ETag, location, and response format.
`facts.AdminClient` invokes the public administration endpoint using user bearer
credentials. Its requests and responses are also defined in `pkg/facts`.

| Claim | Meaning |
|---|---|
| `iss` | OpenSSH SHA256 fingerprint of the signing key |
| `aud` | `epithet-directory` or `epithet-inventory` |
| `iat`, `exp` | Unix seconds; token lifetime is 60 seconds |
| `jti` | Random request identifier |
| `htm` | Exact HTTP method |
| `htu` | HTTP authority plus escaped path and raw query, e.g. `facts.example/lookup?id=a%2Bb` |
| `bh` | Unpadded base64url SHA256 digest of the body; empty-body digest for GET |

Verify signature, audience, expiry and issued-at freshness, method, target including query,
and body digest. Algorithms follow the SSH key type: Ed25519 uses EdDSA, RSA
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
[inventory.md](inventory.md) for deployment configuration. Bespoke providers do not
need Epithet's private `/manage`, `/actor`, or `/scim` backend endpoints.

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
complete operations; each backend owns atomic changes, conflicts, audit history,
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
maximum of 1,000. `inventory list` and `inventory token list` accept `--after FULL_ID`
and `--limit N`; `inventory list --pending` filters before applying the page limit.
Host pages are selected by ID, then sorted by name for display. A full host page
prints its continuation ID to stderr, preserving the concise stdout table.
Token pages include their full IDs in YAML. Continue from the last ID in a token
page; for hosts, use the continuation ID rather than the last displayed name.

`inventory audit --after SEQUENCE --limit N` uses the same page bounds. Events
include a stable, increasing `sequence`; timestamps do not define pagination.
Sequences are never reused after deletion or restart. The last event's sequence
is the next cursor. An empty page ends enumeration; separate pages may observe
concurrent changes. A full page can be followed by an empty one.

Control requests use `after`, `limit`, and `pending` for host lists, `after` and
`limit` for token lists, and `audit-after` and `audit-limit` for inventory or
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
