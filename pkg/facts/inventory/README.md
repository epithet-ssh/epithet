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
transactions. Every mutation commits records, token state, and audit together. Run `storetest.Run` with one fresh inventory to exercise the
contract against another backend. The factory returns one
`storetest.Backend{Hosts: data, Store: management}` value pairing the independent
data and management views. The factory owns its cleanup.

Resource versioning is optional. `SupportsVersioning()` declares whether the
store returns nonempty `Host.Version` values. Versions are opaque strings;
callers compare them only for equality and pass them back as `expectedVersion`
in `UpsertHost` write conditions and to `RemoveHost`. An empty expected version requests no version
check. Stores without versioning return empty versions and callers pass empty
preconditions. Enforcement and atomicity are backend properties. SQLite supports
versioning and keeps its numeric counter entirely inside the adapter.

`Host` contains names, authorization facts, and enrollment metadata. Names may be
exact hostnames or wildcard expressions in the same collection. There is no
separate pattern resource or proposal object. `Enroll` accepts exact names and
creates pending state (or redeems a token). All creation and updates use
`UpsertHost`; reads and removal use `GetHost`, `ListHosts`, and `RemoveHost`.
Administrator creation may include exact or wildcard names.

Storage owns the distinction between exact and wildcard names. SQLite indexes
that distinction per name: lookup checks exact names first, then reads only
wildcard names when there is no active exact match. A wildcard match supplies the
requested hostname and the matching record's facts, without assigning that
record's management identity to the synthesized host. Multiple matching names on
one record are unambiguous; matching different records is a conflict.

Epithet generates IDs with `inventory.NewID` before calling storage. Token
credentials become the enrolled host ID. Tokens do not create host reservations. Each mutation receives an `AuditEvent`
containing the authenticated actor, action, resource ID and operation timestamp.
Storage preserves every field; it does not construct or
complete audit events. Record timestamps use the supplied event time. Removal
retains audit history and appends the supplied removal event.

`UpsertHost(ctx, host, conditions, event)` addresses `host.ID`. Its
`WriteConditions` carries an optional `ExpectedVersion`, `CreateOnly` to forbid
replacing existing facts, and `ConsumeToken` to require the single-use credential
matching the host ID. The zero value permits an ordinary upsert. Enrollment sets
`CreateOnly` and, for preapproval, `ConsumeToken`; identical retries return the
stored host without changing its status or audit history. Administrator writes
use the optional version condition. Validation and review policy stay above
storage; the backend applies these write conditions with persistence.

SQLite uses schema version 5, with indexed exact/wildcard names, retained audit
history, and no inventory-wide revision counter. Older schema
versions are rejected without modification; there is no automatic migration.

Epithet owns enrollment and review policy:

- `Enroll` validates the submitted facts and creates a pending host, or calls
  `UpsertHost` to create the host and consume its token in one storage operation.
  SQLite commits activation, token consumption, and the supplied audit event in
  one transaction; a failed operation leaves the token usable.
- `Review` validates administrator edits and approval/denial transitions before
  storage, and selects the audit action.
- `Creation` and `Replacement` prepare records for persistence.
  `Replacement` checks metadata and an optional expected version; it does not
  impose the administrator review workflow on storage.
- `NewAuditEvent` constructs events before storage. Each mutation persists the
  supplied event, including token activation, without a separate redemption event.

Adapters enforce active exact-name/pattern uniqueness. Realms may be shared
across records with independent labels and account restrictions, including
generated realms. Pending and denied records do not reserve names. Enrollment
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
Link-Template: "/inventory/records{/id}{?after,limit,pending}"; rel="https://epithet.dev/rel/inventory-records"
Link-Template: "/inventory/tokens{?token}"; rel="https://epithet.dev/rel/inventory-tokens"
Link-Template: "/inventory/audit{?cursor,limit}"; rel="https://epithet.dev/rel/inventory-audit"
```

These paths belong to the provider. Clients expand RFC 6570 templates and resolve
relative results against the discovery URL. No resource-level OPTIONS is needed.
[RFC 9652](https://www.rfc-editor.org/rfc/rfc9652.html) defines Link-Template.

| Template / target | Methods | Result |
|---|---|---|
| records, no id | GET | 200, JSON array of records |
| records, no id | POST | administrator creation, 201 |
| records, id | PUT without actor | enrollment or identical retry, 200 |
| records, id | GET, PUT | 200, complete record plus ETag |
| records, id | DELETE | 204 |
| tokens, no token | POST | 201, new token and expiry |
| tokens, token | DELETE | 204 |
| audit | GET | 200, audit page with `events` and optional `next` |

There is no token retrieval. Record list uses `after` (exclusive record ID),
`limit` (0/default 100, max 1000), and `pending`. Audit uses an opaque `cursor` and `limit`. Empty cursor starts a read;
pass the returned `next` back unchanged. Empty `next` means no further page.
Ordering, consistency during writes, and cursor lifetime are backend properties.
Event timestamps need not be unique or monotonic. The CLI accepts `--cursor` and
prints the page including `next`. List entries carry no version; GET the selected item before review.

GET and PUT share this representation:

```json
{
  "id": "record-id",
  "status": "pending",
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

Administrator PUT echoes id and timestamps unchanged. It either replaces host attributes while
retaining status or changes a pending record to active/denied without modifying
host attributes. Combined edit and review is rejected. A successful mutation
returns the committed record and a new ETag when versioning is supported. Name/pattern conflicts return 409.

Enrollment uses PUT to the records URL with the client-selected `id`. It carries
`{"host": {...}}` and, for preapproval, `"token": "credential"` equal to that ID.
Control signs the request without an administrator actor. Pending submissions
require the shared enrollment bearer at control; it never reaches inventory.
Preapproved enrollment validates and consumes the token while creating an active
host. Both paths accept identical retries without another write or audit event.
Enrollment accepts exact names only and does not use If-Match. It cannot edit an
existing host or undo an administrator's review.

Administrator POST to the collection accepts `{"host": {...}}` and creates an
active host with exact or wildcard names. Responses include the record, ETag when
supported, and Location.

POST tokens accepts `{"lifetimeSeconds": 3600}` (0 defaults to one hour; maximum
24 hours), returning `{"token": "credential", "expiresAt": "..."}`. DELETE
expands the known credential into the template's `token` variable. Invalid,
expired or revoked credentials cannot create a host (403). A consumed credential
only permits an identical retry of its existing host. Missing resources
return 404; storage failures return 503. Errors use `{"error": "message"}`.

## Authentication and CLI

Providers accept request-bound service JWTs signed by control, with audience
`epithet-inventory`. The signed subject carries the already authorized actor;
CA reader credentials cannot mutate. Control owns OIDC and the `inventory-admin`
grant. Human CLI operations continue through the agent.

Pending host enrollment requires the control plane's shared bearer credential,
configured with `--enrollment-token-file FILE` or `--enrollment-token SECRET`.
Without it, pending enrollment is disabled. This credential permits only submitting
pending hosts; it grants no inventory reads, edits, approval, token management, or
SCIM access. Control validates it and sends the ordinary signed enrollment request
to the provider. The shared secret never reaches inventory or its storage adapter.

Configure the control service (including when launched by `epithet server`) with:

```toml
enrollment-token-file = "/etc/epithet/enrollment-token"
```

The public client sends PUT to the control URL followed by the host ID. Host
enrollment persists that ID in an `id` file beside `realm` and the CA public key
before submitting. Pending enrollment generates it once; preapproval uses the
single-use credential. Rerunning enrollment reuses the stored ID.

Supply the same secret on an enrolling host:

```sh
epithet host enroll --ca https://ca.example/ \
  --enrollment-token-file /path/to/enrollment-token
```

The client sends this secret in `Authorization: Bearer ...` to control. The host
remains pending until an administrator approves it. The existing `--token` and
`--token-file` options carry a single-use preapproval credential instead; that
path does not require the shared pending-enrollment secret.

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
envelope. `inventory token list` has been removed. Use token create to receive a
credential and token revoke with the known credential to withdraw it.
