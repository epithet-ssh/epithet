# File-backed dynamic inventory: first implementation

This implements the enrollment and administration workflow discussed on September
11–12, 2026. Managed hosts are enabled by default, alongside static host records.
Select `inventory-mode = "static"` to disable managed host storage and
enrollment. Local-only `host enroll` still works when the CA advertises no
inventory link or the advertised endpoint has no enrollment capability.
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
- Exact static hosts win over accepted dynamic exact records, which win over patterns.
  Pending proposals do not affect resolution. Removal deletes the dynamic record.
  Competing pending requests cannot both be approved.
- This milestone manages hosts, including shared named principal domains. User source selection is independent; [SCIM provisioning](scim.md) can now
  manage users. Role grants and named-domain declarations remain static.

## Try it

Add the following to an existing combined-server configuration:

```toml
inventory-admin-user = ["YOUR_EXISTING_DIRECTORY_ID"]
inventory-static-file = ["/etc/epithet/directory-and-static-hosts.yaml"]
```

The ID is the same directory `id` used for certificate issuance. The user must
exist and be active; groups come from directory facts, not client JWT claims.
These grants confer only inventory administration. Directory administration has
its own `directory-admin-user` and `directory-admin-group` grants.

The [combined deployment](inventory.md#combined-deployment) runs separate CA,
control, directory, inventory, and router processes. Configure distinct persistent
CA and control keys. The router forwards `/inventory` directly to control and
`/scim/v2/…` to its provisioning endpoint. CA advertises control without proxying it:

```http
Link: <inventory>; rel="https://epithet.dev/rel/control"
```

An existing reverse proxy forwarding all traffic to `listen` needs no
routing changes. See the [deployment guide](inventory.md) for OIDC, keys, and
migration of older settings.

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

Commands inherit the configured `agent-name` (otherwise `default`). Use
`--agent-name PROFILE` or `--broker-socket SOCKET` to override the selection. A full
record ID always works; unique ID prefixes and unambiguous exact host names also
work. If multiple proposals share a name, use the record ID.

`inventory list` prints one tab-separated row per host with its ID, status, source, and DNS names
or pattern, sorted by the displayed `NAMES` column. Dynamic IDs are shown as
12-character prefixes. Use `inventory show`
for the full record, including accounts, labels, principal domain, and audit metadata.

## Enrollment and review

On the machine being enrolled, run as root:

```sh
epithet host enroll --ca https://ca.example/
```

The command fetches the CA key and prepares local configuration without installing
it. It reuses an existing principal domain or generates one in memory for review.
Use `--principal-domain fleet` to propose a specific domain. It
proposes the local hostname, appending the configured search-domain suffix when
it is missing. This reads local configuration and sends no
DNS queries. Use
repeatable `--host-name` flags to override that guess. It proposes accounts with shells
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

The domain shown in the real proposal is the installed domain, the value supplied
with `--principal-domain`, or a valid identifier generated locally. You can edit
`domain` before installation; the reviewed value is both installed locally and
submitted to inventory. An existing domain file must match the chosen value;
enrollment does not replace an installed domain. Principal mode must match local
enrollment settings; select it with `--principal-mode`.

Domains prefixed with `epithet-host-id-v1:` remain unique to an active host.
Unprefixed names such as `fleet` are named domains and require
`principal-mode: epithet-principal-v1`. Declare them in the static inventory:

```yaml
domains: [fleet]
```

Approval and token admission reject undeclared named domains. All active members
of a shared domain, including static hosts and patterns, must have identical labels
and account restrictions. Account order does not matter, but `null` and `[]` differ.
Writ evaluates each resolved host using its names, labels, and account restrictions.
The principal domain is separate issuance metadata and never replaces host names.

A successful editor exit with valid YAML proceeds to local setup and submission. Invalid YAML
produces an error and an edit/cancel choice. Unknown fields, multiple YAML documents,
invalid names, and omitted `accounts` are errors. Emptying the file also cancels;
an unsuccessful editor exit aborts. Cancellation leaves persistent state unchanged:
no CA-key or principal-domain files are installed, and sshd is untouched.

`accounts: []` permits no accounts. Explicit `accounts: null` means ungrounded,
leaving account selection to issuance policy. A list restricts issuance to those
accounts. There is no silent omitted-field default in managed proposals.

After a valid editor exit, enrollment installs the reviewed domain and CA key,
then configures, validates, and reloads sshd before submitting the proposal.
A local setup failure prevents submission. It prints `RECORD_ID` and
`pending` or `active`, separated by a tab, and exits. It does not poll. If
submission fails or is rejected, local setup remains installed and the error
reports that registration did not complete. A rerun prepares, reviews, configures,
and submits again. It reuses matching local identity and trust files; unchanged
sshd configuration is validated without reloading. A configured managed endpoint
failure never becomes a silent local-only enrollment.

Admin edits to a domain affect subsequent issuance but do not yet update the
target's installed domain file. Scheduled host checks to adopt domain changes
made during approval or later edits are tracked in YATL task `508fj5h3`.

`inventory approve HOST_ID` prints the complete record and prompts:

```text
approve / edit / deny / [exit: default on Enter]:
```

Editing returns to review. Approval and denial are explicit; exit does nothing.
Editing alone preserves admission status. Admin edits to principal settings do
not reconfigure the remote sshd; those settings must remain aligned with the host.
A stale revision is rejected, and the
review command reloads before presenting another choice. Approval changes the host status to `active`. Once active, a host
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
epithet host enroll --ca https://ca.example/ --token TOKEN_VALUE
epithet host enroll --ca https://ca.example/ --token-file ./token.txt
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
Creating a token creates a pending host with no attributes and an enrollment
credential. Redemption fills in that host and activates it under the same ID,
preserving its creation time and incrementing its revision. Pending reservations
appear in administrative host listings but supply no issuance facts. An empty
reservation cannot be approved until valid host attributes have been supplied. Enrollment without a token allocates an ID
and creates a pending host file directly. New filename publication is exclusive:
a collision cannot overwrite an existing record.
Each submission is a new enrollment. There is no persistent enrollment credential
or automatic recovery of an earlier response. Rerunning submits a new proposal,
including after a lost response; it does not resume or reconcile a previous record.
A consumed token stays consumed and is rejected if supplied again.

Pending proposals may overlap other pending proposals, active dynamic hosts,
and exact static records. They cannot be approved until the conflict is resolved.
Token enrollment approves immediately, so it rejects an overlapping name without
consuming the token. Approval checks uniqueness while holding the same lock as its write. Conflicts must be resolved by
editing the pending record or changing the existing record through its owning
source. Generated per-host principal domains must likewise be unique among
admitted hosts; shared-domain enrollment is deferred.

A denied or removed host can submit again, receiving a new pending record ID.
Previous approval is never restored. Retrying with an already-consumed token does
not bypass this. Removal deletes the dynamic record, so normal static lookup applies again. It
does not revoke certificates already issued or clear certificates held by agents.

Lookup precedence is:

1. Exact static record.
2. Approved dynamic exact records. Pending and denied proposals do not affect
   resolution.
3. Static wildcard patterns in their existing configured order.

Static records are read-only through the API. Listings include static exact and
pattern records with their source file, plus dynamic records and any names
shadowed by static records. Removing a static override exposes underlying dynamic
state again. Renaming or removing an active record releases its former names;
normal static lookup, including wildcard patterns, applies to those names again.

Anonymous enrollment has a global burst limit of 20 and sustained rate of one
request per second, and at most 1,000 pending records. Name-conflict responses do
not disclose the conflicting record. They still reveal whether a proposed name
is available; this implementation reduces abuse rather than eliminating name
enumeration. Pending proposals cannot change existing static or dynamic admission.

## Files, durability, and recovery

The host storage layout beneath `state-dir` is:

```text
inventory/
  inventory.lock
  records/
    <token-or-host-id>.yaml
    <another-id>.yaml
```

A pending host reservation contains the enrollment credential expiry and audit history:

```yaml
version: 2
kind: host
host:
  id: TOKEN_VALUE
  revision: 1
  status: pending
  created-at: 2026-09-12T11:00:00Z
  updated-at: 2026-09-12T11:00:00Z
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

After redemption, the same host becomes active and its token metadata has
`used-by` equal to that host ID. The previously absent `host.host` mapping contains
the editable names, labels, accounts, and principal settings. `host.status`
records admission. Its `audit` list includes token creation and enrollment events.
Approval, editing, and token revocation replace only the affected item file.
Removal deletes the item file, including its audit history and consumed token
metadata, and syncs the directory before updating the in-memory indexes. A missing
token file cannot be redeemed. Audit inspection combines the surviving per-item
histories in timestamp order.

One inventory process owns the directory through an OS file lock. Directories
are created with mode 0700 and files with mode 0600. A new item is fully written
and synced in a temporary file, then published through an exclusive hard link.
Activating a pending reservation uses atomic rename of a synced temporary file,
followed by directory sync on Unix. The admission, consumption, and audit event
are all in that one file: there is no transaction journal or multi-file commit
for redemption. Interrupted temporary writes are ignored at startup.

At startup (and with `inventory --check`), inventory scans and validates the item files and builds maps
for records by ID, active names to record IDs, and active
principal domains. **Hostname resolution does not scan files or host records.** Admission and conflict checks use these
indexes too. The check command takes the same store lock as startup, so stop the
writer before checking managed files. Mutations hold the write lock, persist the changed file, then update
only that record's index entries before allowing another reader or writer.
Content revisions are calculated from in-memory per-item hashes; no index file
is persisted. Unchanged restarts produce the same revision.

When `inventory-mode = "enrollment"` is selected, unreadable or invalid dynamic storage
fails startup. Duplicate active names are validation errors, never a reason to
choose an arbitrary winner. To run static-only, select `inventory-mode = "static"`.
`state-dir` is the shared storage root, defaulting to Epithet's native system
state directory. Managed host storage lives in its `inventory/` subdirectory;
SCIM directory storage lives in `directory/`. The path only overrides storage
location. Configurations that previously pointed directly to the host-state
directory must instead point to its parent, with host state under `inventory/`.
The service user needs write access to that directory. No files are moved
automatically, and `inventory --check` opens managed host storage by default.
Static exact records override dynamic records during normal operation. A write
failure disables all lookups and operations through the managed store until
repair/restart, including exact static lookups; it never switches to static-only service. Windows cannot
provide the same directory-fsync step through Go's file API.

For emergency repair: **stop inventory, grep/edit `inventory/records/*.yaml`
beneath `state-dir`, restart**.
There is no index to repair separately. Keep each ID equal to its filename,
and use `pending`, `active`, or `denied` for host status. Delete a host file to
remove its dynamic record. Live edits are not watched: the
process continues reading its in-memory version, and its next write to that
item replaces external changes. Keep a backup before manual edits.

When upgrading from the former `approved` status, stop the service and change
each host's `status: approved` to `status: active` in its record file before
starting the new version. Leave approval audit events unchanged. This rename
has no automatic migration; the old status is rejected during startup validation.

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

Standalone inventory serves the CA-authenticated resolution endpoint; control
serves public management at `/manage`. Configure the CA with the private inventory
resolver URL and the client-reachable control URL:

```toml
control-public = "https://control.example/manage"
inventory = "https://inventory.internal.example/"
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
redemption, token expiry/revocation/retries, static precedence, wildcard lookup after rename/removal,
corruption recovery, immutable snapshots, actual configured OIDC claim mapping,
active users and group grants, cross-origin discovery and redirect refusal,
editor cancellation/retry, and local sshd setup ordering. A combined-server test
runs real admin CLI commands through an agent and verifies that wildcard-based
issuance continues while pending, approval takes effect, and removal restores
static wildcard lookup.
