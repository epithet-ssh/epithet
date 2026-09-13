# File-backed dynamic inventory: first implementation

This implements the enrollment and administration workflow discussed on September
11–12, 2026. Enable it with `inventory.state-dir`. Existing static deployments keep
working, including local-only `host enroll` when the CA advertises no inventory
link. Nothing has been deployed or enabled on a real host as part of this change.
The [follow-up audit](dynamic-inventory-audit.md) distinguishes corrected workflow
errors from implementation assumptions that still need design review.

## Decisions made during implementation

- One YAML file holds each token or host and its audit history; one process owns the
  directory. Hostname indexes are rebuilt at startup and updated in memory.
- Inventory administration uses the existing agent session and one static admin role.
- The combined server puts a plain HTTP router in front of private CA, inventory,
  and policy Unix sockets. TLS and ACME stay in the deployment's front end.
- Enrollment generates YAML, opens the editor, and submits after a valid editor exit.
  Parse and validation errors offer re-editing. No separate host retry secret is created.
- Tokens have no templates, default to one hour, and support copy/paste or files.
  The literal token is its filename and becomes the admitted host ID.
- Exact static hosts win over dynamic admission state, which wins over patterns.
  Removal leaves tombstones, and competing pending requests cannot both be approved.
- This milestone manages hosts. Users and role grants remain static; SCIM, shared
  principal domains, direct host addition, and databases are deferred.

## Try it

Add the following to an existing combined-server configuration:

```yaml
inventory:
  static:
    - /etc/epithet/directory-and-static-hosts.yaml
  state-dir: /var/lib/epithet/inventory
  admin-user:
    - YOUR_EXISTING_DIRECTORY_ID
  # Alternatively, or additionally:
  admin-group:
    - inventory-operators
  oidc:
    issuer: https://your-existing-issuer.example
    client-id: your-existing-client-id
    # Keep your existing identity-mode and user-id-claim settings.
```

The ID in `admin-user` is the same `users[].id` used for certificate issuance.
The user's record must exist and be active. `admin-group` matches memberships
from that directory record, not arbitrary group claims submitted by the client.
Both grant the single `inventory-admin` role; there are no custom roles or Writ
rules for inventory administration. User records and grants are static in this
first implementation. SCIM and dynamic user provisioning remain later work.

Start `epithet --config server.yaml server` as usual. A separate router process
owns `server.listen`; CA, inventory, and policy each listen on a private Unix
socket. When the inventory child has managed storage configured, the router
forwards `/inventory` to that child's `/manage` endpoint. Other paths go to CA.
The CA advertises this bootstrap header and does not proxy management requests:

```http
Link: <inventory>; rel="https://epithet.dev/rel/inventory"
```

For `https://ca.example/`, that target is `https://ca.example/inventory`. Keep
Caddy terminating TLS and proxying HTTP to the existing `server.listen` address;
it does not need separate inventory routing. See the
[combined deployment example](inventory.md#combined-deployment). Authentication
and authorization stay in their services, and the router adds no credentials.

On the admin machine, start or restart the agent with the updated executable and
the usual CA configuration. At startup, the agent discovers the public inventory
URL from the CA and binds its inventory client to that endpoint. Restart the agent
after changing the advertised URL. Administration reuses that agent's OIDC login:

```sh
epithet inventory list --pending
epithet inventory show HOST_ID
epithet inventory approve HOST_ID
epithet inventory edit HOST_ID
epithet inventory remove HOST_ID
epithet inventory audit
```

Commands accept `--name PROFILE` or `--broker SOCKET` to select an agent. A full
record ID always works; unique ID prefixes and unambiguous exact host names also
work. Old removed records can make a name ambiguous, so use the current ID.

## Enrollment and review

On the machine being enrolled, run as root:

```sh
epithet host enroll --ca-url https://ca.example/
```

The command fetches the CA key and prepares durable local identity state. It
proposes the local hostname, appending the configured search-domain suffix when
it is missing. This reads local configuration and sends no
DNS queries. Use
repeatable `--name` flags to override that guess. It proposes accounts with shells
that appear to permit login, using local passwd data and macOS Directory Services.
These are guesses, not a determination of effective PAM/sshd access. Windows
currently starts with an empty account proposal, which the operator must edit.

The proposal opens in `$EDITOR`, or `vi` if unset:

```yaml
names:
  - freki.example
labels: {}
accounts:
  - brianm
principal-mode: epithet-principal-v1
domain: epithet-host-id-v1:THE_HOSTS_GENERATED_DOMAIN
```

The domain shown in the real proposal is the valid identifier generated locally.
Domain and principal mode must match local enrollment settings; validation
explains a mismatch and offers to reopen the editor. Select the mode with the
existing `--principal-mode` flag. Other proposal fields are editable.

A successful editor exit with valid YAML submits the proposal. Invalid YAML
produces an error and an edit/cancel choice. Unknown fields, multiple YAML documents,
invalid names, and omitted `accounts` are errors. Emptying the file also cancels;
an unsuccessful editor exit aborts. Cancellation leaves sshd untouched, although
the initial CA-key and principal-domain files may already have been prepared.

`accounts: []` permits no accounts. Explicit `accounts: null` means ungrounded,
leaving account selection to issuance policy. A list restricts issuance to those
accounts. There is no silent omitted-field default in managed proposals.

After a valid editor exit, enrollment configures and validates sshd using the existing
rollback-aware setup, then submits the proposal. It prints `RECORD_ID` and
`pending` or `approved`, separated by a tab, and exits. It does not poll. If
submission fails, sshd remains configured and the error explicitly tells the
operator to check inventory before submitting again. A configured managed endpoint failure never becomes a silent
local-only enrollment.

`inventory approve HOST_ID` prints the complete record and prompts:

```text
Approve / Edit / Deny / Exit [exit]:
```

Editing returns to review. Approval and denial are explicit; exit does nothing.
Editing alone preserves admission status. Admin edits to principal settings do
not reconfigure the remote sshd; those settings must remain aligned with the host.
A stale revision is rejected, and the
review command reloads before presenting another choice. Once approved, a host
can be used without rerunning enrollment, subject to ordinary certificate policy.

Enrollment always uses the editor. There is no proposal-file or noninteractive
submission mode, and no `inventory add` command in this milestone.

## Tokens

```sh
epithet inventory token create                 # defaults to one hour
epithet inventory token create --expires-in 30m
epithet inventory token create --quiet         # only the secret value
epithet inventory token list
epithet inventory token revoke TOKEN_ID
```

Normal creation prints metadata and a shell-quoted, ready-to-copy enrollment
command with the agent's CA URL. The token value is the secret:

```sh
epithet host enroll --ca-url https://ca.example/ --token TOKEN_VALUE
epithet host enroll --ca-url https://ca.example/ --token-file ./token.txt
```

The two inputs are mutually exclusive. Tokens are random 256-bit values. The
literal value is the filename and the reserved host ID; filenames are not hashed.
The inventory filesystem is trusted and protected by ordinary permissions.
Admin token listings and per-item audit entries consequently expose token IDs,
which are usable preapproval credentials until consumed, revoked, or expired.
The initial configurable lifetime range is one second to 24 hours, with a
one-hour default. Token expiry has no effect on an already admitted host.

There are **no constrained enrollment templates** yet. A token holder chooses the
proposal's names, labels, and accounts. Redemption performs normal validation and
conflict checks, then consumes the token and admits the host in one durable
transaction. Conflicts do not consume tokens. Expired, revoked, or used tokens
cannot approve another host.

## Identity, retries, and conflicts

Records have random, immutable IDs distinct from names and principal domains.
Creating a token reserves the future host ID. Redemption transforms its file into
the host record under that same ID. Enrollment without a token allocates an ID
and creates a pending host file directly. New filename publication is exclusive:
a collision cannot overwrite an existing record.
Each submission is a new enrollment. There is no persistent enrollment credential
or automatic recovery of an earlier response. If a response is lost, the operator
checks inventory before submitting again. A consumed token stays consumed; a new
token or a new pending request is needed if another enrollment is appropriate.

Pending proposals may overlap other pending proposals, approved dynamic hosts,
and exact static records. They cannot be approved until the conflict is resolved.
Token enrollment approves immediately, so it rejects an overlapping name without
consuming the token. Approval checks uniqueness while holding the same lock as its write. Conflicts must be resolved by
editing the pending record or changing the existing record through its owning
source. Generated per-host principal domains must likewise be unique among
admitted hosts; shared-domain enrollment is deferred.

A denied or removed host can submit again, receiving a new pending record ID.
Previous approval is never restored. Retrying with an already-consumed token does
not bypass this. Removal prevents new certificate issuance for that record; it
does not revoke certificates already issued or clear certificates held by agents.

Lookup precedence is:

1. Exact static record.
2. Exact dynamic admission state: approved hosts resolve; pending, denied, and
   removed records prevent wildcard fallback. An approved record takes precedence
   over competing pending/retired claims to that name.
3. Static wildcard patterns in their existing configured order.

Static records are read-only through the API. Listings include static exact and
pattern records with their source file, plus dynamic records and any names
shadowed by static records. Removing a static override exposes underlying dynamic
state again. Editing names retains tombstones for retired names so removal or
renaming cannot silently fall back to a wildcard grant.

Anonymous enrollment has a global burst limit of 20 and sustained rate of one
request per second, and at most 1,000 pending records. Name-conflict responses do
not disclose the conflicting record. They still reveal whether a proposed name
is available; this implementation reduces abuse rather than eliminating name
enumeration. Pending claims can also mask static wildcard access. Use exact static
entries for recovery hosts and trusted static admission.

## Files, durability, and recovery

The directory layout is:

```text
inventory/
  inventory.lock
  records/
    <token-or-host-id>.yaml
    <another-id>.yaml
```

An unused token file contains its expiry and audit history:

```yaml
version: 2
kind: token
token:
  id: TOKEN_VALUE
  expires-at: 2026-09-12T12:00:00Z
  revoked: false
audit:
  - at: 2026-09-12T11:00:00Z
    actor: ADMIN_DIRECTORY_ID
    action: token-create
    resource: TOKEN_VALUE
```

After redemption, the same file has `kind: host`, a `host` record, and token
metadata with `used-by` equal to that host ID. The `host.host` mapping contains
the editable names, labels, accounts, and principal settings. `host.status`
records admission; `host.retired-names` preserves names removed by API edits.
Its `audit` list includes the token creation and enrollment events. Approval,
editing, removal, and revocation replace only the affected item file. Audit
inspection combines the per-item histories in timestamp order.

One inventory process owns the directory through an OS file lock. Directories
are created with mode 0700 and files with mode 0600. A new item is fully written
and synced in a temporary file, then published through an exclusive hard link.
Replacing a token with its host uses atomic rename of a synced temporary file,
followed by directory sync on Unix. The admission, consumption, and audit event
are all in that one file: there is no transaction journal or multi-file commit
for redemption. Interrupted temporary writes are ignored at startup.

At startup (and with `inventory --check`), inventory scans and validates the item files and builds maps
for records by ID, names (approved owner plus pending/retired claims), and approved
principal domains. **Hostname resolution does not scan files or host records.** Admission and conflict checks use these
indexes too. The check command takes the same store lock as startup, so stop the
writer before checking managed files. Mutations hold the write lock, persist the changed file, then update
only that record's index entries before allowing another reader or writer.
Content revisions are calculated from in-memory per-item hashes; no index file
is persisted. Unchanged restarts produce the same revision.

When `inventory.state-dir` is configured, unreadable or invalid dynamic storage
fails startup. Duplicate approved names are validation errors, never a reason to
choose an arbitrary winner. To run static-only, leave `inventory.state-dir` unset.
Static exact records override dynamic records during normal operation. A write
failure disables all lookups and operations through the managed store until
repair/restart, including exact static lookups; it never switches to static-only service. Windows cannot
provide the same directory-fsync step through Go's file API.

For emergency repair: **stop inventory, grep/edit `records/*.yaml`, restart**.
There is no index to repair separately. Keep each ID equal to its filename,
preserve admission state, and retain `retired-names` when
renaming a host offline. Deleting a host file deletes its tombstones too; mark it
`removed` when access should stay withdrawn. Live edits are not watched: the
process continues reading its in-memory version, and its next write to that
item replaces external changes. Keep a backup before manual edits.

A snapshot of the directory captures the authoritative records without derived
indexes. Copy/restore with the writer stopped for a coherent ordinary file copy;
a filesystem snapshot can capture a point in time. Restoring older data can
resurrect approvals or unused tokens. Multi-writer replication, a static-directory
reader, and object-store coordination are possible follow-ups, not implemented
features. This version uses a single writer and local filesystem semantics.

Reads already in flight may complete using their earlier revision, even after
removal. Neither file replacement nor reindexing revokes certificates already
issued. Static configuration and role changes still require restart. There is
no audit compaction, pagination, SCIM, database backend, or configurable RBAC yet.

## Separate deployment and protocol

Standalone inventory serves the existing CA-authenticated resolution endpoint,
plus a separate `/manage` endpoint when managed storage is enabled. Configure the
CA with both its private resolver URL and the client-reachable URL:

```yaml
ca:
  inventory: https://inventory.internal.example/
  inventory-public-url: https://inventory.example/manage
```

The CA advertises configured capability independently of backend health. Clients
may follow the explicit inventory relation to another HTTPS origin; they never
forward credentials through HTTP redirects. Only explicit `--insecure` permits
HTTP in local development. Reverse proxies can mount the endpoint elsewhere,
provided the advertised URL routes to `/manage`.

The managed endpoint uses GET for capability discovery and POST for an operation
request. It is separate from resolution version 2; the existing resolution wire
contract and Writ facts are unchanged. Admin POST requests use OIDC bearer
credentials. Enrollment submits a proposal and an optional one-use token.
The broker sends admin requests to the CA-advertised endpoint itself, so neither
an admin CLI destination override nor a local response exposes the OIDC token.
A 401 triggers one broker refresh/retry; permission denials do not.

## Validation

Tests cover per-item updates, exclusive creation, startup index reconstruction,
offline repair, interrupted redemption before/after replacement,
durable restart, locking, stale edits, concurrent approvals and token
redemption, token expiry/revocation/retries, static precedence, wildcard tombstones,
corruption recovery, immutable snapshots, actual configured OIDC claim mapping,
active users and group grants, cross-origin discovery and redirect refusal,
editor cancellation/retry, and local sshd setup ordering. A combined-server test
runs real admin CLI commands through an agent and verifies that issuance is denied
while pending, allowed after approval, and denied after removal.
