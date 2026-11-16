# Managed inventory providers

Use `factserver.InventoryHandler(data, caPublicKey, controlPublicKey,
factserver.WithInventoryManagement(management))` to serve facts and the inventory
management API. `data` implements `inventory.Hosts`; `management` implements
`inventory.Store`. The interfaces are independent: use the same instance twice
or separate implementations describing the same logical inventory. Omitting the
option serves facts only, even if `data` also implements management. The executable
opens its store, owns its lifetime and listener, and configures the trusted keys. An empty control key
turns off management. The shared packages have no cloud SDK dependencies.

`Store` exposes complete operations rather than transactions or database rows.
An adapter implements its database schema, queries, conditional writes and
transactions. Every mutation commits records and audit together. Run `storetest.Run` with one fresh inventory to exercise the
contract against another backend. The factory returns one
`storetest.Backend{Hosts: data, Store: management}` value pairing the independent
data and management views. The factory owns its cleanup.

Resource versioning is optional. `SupportsVersioning()` declares whether the
store returns nonempty `Host.Version` values. Versions are opaque strings;
callers compare them only for equality and pass them back as `expectedVersion`
in `UpsertHost` write conditions and to `RemoveHost`. An empty expected version requests no version
check. Stores without versioning return empty versions and callers pass empty
preconditions. Other enforcement and consistency properties belong to the backend.
Creation-only writes must atomically create, return an identical retry unchanged,
or conflict on differing facts, including concurrent calls. SQLite supports
versioning and keeps its numeric counter entirely inside the adapter.

`Host` contains names, authorization facts, and enrollment metadata. Names may be
exact hostnames or wildcard expressions in the same collection. There is no
separate pattern resource or proposal object. `CreateHost` accepts both kinds
of name and creates active records. All creation and updates use
`UpsertHost`; reads and removal use `GetHost`, `ListHosts`, and `RemoveHost`.

Storage owns the distinction between exact and wildcard names. SQLite indexes
that distinction per name: lookup checks exact names first, then reads only
wildcard names when there is no active exact match. A wildcard match supplies the
requested hostname and the matching record's facts, without assigning that
record's management identity to the synthesized host. Multiple matching names on
one record are unambiguous; matching different records is a conflict.

Epithet generates IDs with `inventory.NewID` before calling storage. Host IDs are independent random identities; knowing one grants no authority. Each mutation receives an `AuditEvent`
containing the authenticated actor, action, resource ID and operation timestamp.
Storage preserves every field; it does not construct or
complete audit events. Record timestamps use the supplied event time. Removal
retains audit history and appends the supplied removal event.

`UpsertHost(ctx, host, conditions, event)` addresses `host.ID`. Its
`WriteConditions` carries an optional `ExpectedVersion`, `CreateOnly` to forbid
replacing existing facts. The zero value permits an ordinary upsert. Host creation sets
`CreateOnly`; identical retries return the
stored host without changing its status or audit history. Administrator edits
use the optional version condition. Validation and review policy stay above
storage; the backend applies these write conditions with persistence.

SQLite uses schema version 6, with indexed exact/wildcard names and retained audit
history. Opening version 5 drops its obsolete credential table and advances the
version, preserving host records and audit history. Other older versions are
rejected. There is no pending-record migration or transition workflow.

Epithet owns enrollment authorization and edit policy:

- `CreateHost` validates names and host facts, assigns the caller's ID and
  active status, and calls `UpsertHost` with `CreateOnly`. The provider owns host
  validation and normalization; control forwards the submitted facts unchanged.
  SQLite commits the host and its supplied audit event in one transaction.
- `Host.ValidateEdit` validates administrator edits; lifecycle transitions are not supported.
- `Creation` and `Replacement` prepare persistence metadata and validate records.
- `NewAuditEvent` constructs events with the authenticated actor. Enrollment uses
  the verified JWT subject; unchanged retries produce no duplicate event.

Adapters enforce active exact-name/pattern uniqueness. Realms may be shared
across records with independent labels and account restrictions, including
generated realms. Enrollment
retries with the same ID and facts return the existing record unchanged; different
facts cannot overwrite it. Administrator edits use the same `UpsertHost` operation.

Lookups return host facts without an inventory-wide revision. Exact names win
over patterns; multiple matching active patterns are a conflict. Pattern facts
use the requested hostname. Nil accounts mean unrestricted; an empty slice
means no accounts. Preserve this distinction in storage and detached results.

## HTTP contract

Control discovers management at the **complete configured inventory fact URL**
using a signed `OPTIONS`. Built-in HTTP providers use `/lookup`; Unix socket
configuration uses that built-in path automatically. Any discovery 4xx means
lookup-only support. Successful OPTIONS with no inventory relations also means
lookup-only. Transport failures, redirects, 5xx, malformed templates or partial
inventory relation sets are errors, never fallback. Discovery is not cached.

```http
HTTP/1.1 204 No Content
Allow: GET, OPTIONS
Cache-Control: no-store
Link-Template: "/inventory/records{/id}{?after,limit}"; rel="https://epithet.dev/rel/inventory-records"
Link-Template: "/inventory/audit{?cursor,limit}"; rel="https://epithet.dev/rel/inventory-audit"
```

These paths belong to the provider. Clients expand RFC 6570 templates and resolve
relative results against the discovery URL. No resource-level OPTIONS is needed.
[RFC 9652](https://www.rfc-editor.org/rfc/rfc9652.html) defines Link-Template.

| Template / target | Methods | Result |
|---|---|---|
| records, no id | GET | 200, JSON array of records |
| records, id | POST | create an active host or return an identical retry, 200 |
| records, id | GET; PUT with a complete record | 200, complete record plus ETag |
| records, id | DELETE | 204 |
| audit | GET | 200, audit page with `events` and optional `next` |

Record list uses `after` (exclusive record ID),
`limit` (0/default 100, max 1000). Audit uses an opaque `cursor` and `limit`. Empty cursor starts a read;
pass the returned `next` back unchanged. Empty `next` means no further page.
Ordering, consistency during writes, and cursor lifetime are backend properties.
Event timestamps need not be unique or monotonic. The CLI accepts `--cursor` and
prints the page including `next`. List entries carry no version; GET the selected item before review.

GET and PUT share this representation:

```json
{
  "id": "record-id",
  "status": "active",
  "host": {
    "name": ["web.example"],
    "attributes": {"environment": "production"},
    "accounts": ["deploy"],
    "principal": {"mode": "epithet-principal-v1", "realm": "production-web"}
  },
  "createdAt": "2026-10-14T09:00:00Z",
  "updatedAt": "2026-10-14T09:00:00Z"
}
```

Exact and wildcard names use the same `name` array. Hosts must include `accounts`. Attributes remain
string-valued in managed inventory. Versioned stores return a strong `ETag`, for
example `"backend:opaque/version"`. Administrator PUT and DELETE then require the exact reviewed
tag in `If-Match`; missing preconditions return 428, malformed tags 400, and stale
tags 412. Stores without versioning omit ETag and accept writes without If-Match;
an explicit version precondition against such a store returns 412. The signed
service JWT's `if_match` claim binds this header to the request.

Control exposes the unquoted ETag value as an optional `version` string on host
records. Mutation requests carry `expected-version`. Control preserves the token
without interpreting it numerically; an absent provider ETag yields no version
and no outgoing If-Match.

Administrator PUT echoes id, active status, and timestamps unchanged while replacing
host facts. A successful mutation returns the committed record and a new ETag
when versioning is supported. Name/pattern conflicts return 409.

Host creation uses POST to the records URL with the client-selected `id` and
body `{"host": {...}}`. Control signs the request with the authenticated actor.
Inventory accepts exact and wildcard names and records a `create` audit event.
An identical retry returns the existing record without another audit event.
Different facts conflict (409), including under concurrent requests.
Responses include the record, ETag when supported, and Location. If the returned
record ID differs from the requested ID, control reports HTTP 503. All mutations
require a nonempty signed actor.
Missing resources return 404; storage failures return 503. Errors use
`{"error": "message"}`. Inventory has no token resources or credential storage. Token issuance no longer
produces inventory audit events; enrollment mutations retain their audit events.

## Authentication and CLI

Providers accept request-bound service JWTs signed by control, with audience
`epithet-inventory`. The signed subject carries the already authorized actor;
CA reader credentials cannot mutate. Control owns OIDC and the `inventory-admin`
grant. Human CLI operations continue through the agent.

Control issues reusable enrollment JWTs with the same key and algorithm it uses
for provider requests. The payload
contains only `aud: "epithet-enrollment"`, required `exp` (Unix seconds), and a
required nonempty `sub` naming the provisioning principal. Verification checks
the configured key, audience, expiration without a grace period, and subject.
Enrollment tokens authorize only host creation. Inventory administrators can
create hosts using OIDC or the configured inventory automation credential.
Deployments sharing a signing key share enrollment trust.

Issue through the existing administrator/agent flow:

```sh
epithet inventory token create --subject production-provisioner --expires-in 2160h
epithet host enroll --ca https://ca.example/ --token-file /path/to/enrollment.jwt
```

Both `--subject` and an explicit positive `--expires-in` are required. Lifetimes
are expressed with Go duration syntax and must be at least one second; there is
no default or 24-hour policy cap. `--quiet` prints only the JWT. `--token` accepts
the same credential directly. The host sends `Authorization: Bearer JWT` and
persists an independent random host ID in `id` beside its realm and CA public key
before submitting. Reruns reuse this ID even when the credential changes.

Both `host enroll` and `inventory add` POST to the advertised control URL plus
`/HOST_ID` with `{"action":"create","id":"HOST_ID","host":{...}}`. Host facts use the
control vocabulary (`names`, `labels`, explicit `accounts`, `principal-mode`,
optional `realm`). Success returns HTTP 200 with an active `host` record.
There is no credential in the body. Issuance is an administratively authenticated
POST with `{"action":"token-create","subject":"production-provisioner",
"lifetime-seconds":7776000}`. Its response contains
`{"token":{"token":"JWT","expires-at":"..."}}`.

Each token authorizes multiple otherwise-valid hosts, including supplied labels,
accounts, principal mode, and realm. Audit attributes enrollment to `sub`; it
identifies the credential's provisioning principal, not a unique token or the
person or machine holding it. Expiry limits new enrollment only; existing hosts
remain active and normal user authentication and Writ policy still apply.

Revoke a subject through normal control configuration and restart (including
control launched by `epithet server`):

```toml
denied-subject = ["retired-provisioner", "compromised-provisioner"]
```

The equivalent repeatable flag is `--denied-subject SUBJECT`. Matching
is exact and case-sensitive. All instances must receive the same list. Denied
subjects cannot receive new tokens or enroll using any existing token. Retain
entries operationally: removing one re-enables that subject's unexpired tokens.
Issue replacement credentials to a new subject. There is no individual token
revocation, use counter, history store, or configuration reload mechanism.

The shared pending-enrollment bearer, single-use tokens, pending approval/denial,
and per-token revocation are removed. Existing active hosts remain active.

Control may configure `--inventory-token-file FILE` (or `--inventory-token`) for
automation. This is separate from the SCIM credential and enrollment tokens.
It grants inventory administration only; audit records identify it as
`inventory-token`. Automation can use:

```sh
epithet inventory --control-url https://control.example/manage \
  --admin-token-file /path/to/inventory-admin-token list
```

The public control/agent command envelope remains the CLI transport; control's
provider hop uses the REST contract above. No provider implements that command
envelope. Token issuance belongs to control; providers implement only authorized
host writes and audit retrieval.
