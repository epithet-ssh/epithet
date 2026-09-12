# File-backed dynamic inventory: first implementation

This implements the enrollment and administration workflow discussed on September
11, 2026. Enable it with `inventory.state-dir`. Existing static deployments keep
working, including local-only `host enroll` when the CA advertises no inventory
link. Nothing has been deployed or enabled on a real host as part of this change.

## Decisions made during implementation

- One YAML snapshot holds hosts, tokens, tombstones, and audit; one process owns it.
- Inventory administration uses the existing agent session and one static admin role.
- The combined server advertises inventory automatically and shares its existing port.
- Enrollment uses an editor plus an explicit submit/cancel choice. A durable local
  bearer credential makes retries idempotent; it is separate from the host's ID.
- Tokens have no templates, default to one hour, and support copy/paste or files.
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

Start `epithet --config server.yaml server` as usual. It discovers whether its
inventory child has managed storage configured, exposes only that child's managed
endpoint through the existing listener, and advertises this bootstrap header:

```http
Link: <inventory>; rel="https://epithet.dev/rel/inventory"
```

On the admin machine, start or restart the agent with the updated executable and
the usual CA configuration. Administration reuses that agent's OIDC login:

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
proposes the local hostname and, when available, its canonical DNS name. Use
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

After editing, choose **submit**, **edit**, or **cancel**. Invalid YAML produces
an error and an edit/cancel choice. Unknown fields, multiple YAML documents,
invalid names, and omitted `accounts` are errors. Emptying the file also cancels;
an unsuccessful editor exit aborts. Cancellation leaves sshd untouched, although
the initial CA-key and principal-domain files may already have been prepared.

`accounts: []` permits no accounts. Explicit `accounts: null` means ungrounded,
leaving account selection to issuance policy. A list restricts issuance to those
accounts. There is no silent omitted-field default in managed proposals.

After confirmation, enrollment configures and validates sshd using the existing
rollback-aware setup, then submits the proposal. It prints `RECORD_ID` and
`pending` or `approved`, separated by a tab, and exits. It does not poll. If
submission fails, sshd remains configured and the error explicitly tells the
operator to retry. A configured managed endpoint failure never becomes a silent
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

For automation, prepare a complete YAML proposal and use
`host enroll --proposal-file FILE --yes --ca-url URL`. `--yes` requires the
explicit file and still validates it. Without `--yes`, that file is opened for
review. There is no `inventory add` command in this milestone.

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

The two inputs are mutually exclusive. Tokens are random 256-bit values; only
SHA-256 hashes are persisted. Listings and audit entries never contain secret
values. Creation displays the value once. The initial configurable lifetime range
is one second to 24 hours, with a one-hour default.

There are **no constrained enrollment templates** yet. A token holder chooses the
proposal's names, labels, and accounts. Redemption performs normal validation and
conflict checks, then consumes the token and admits the host in one durable
transaction. Conflicts do not consume tokens. Expired, revoked, or used tokens
cannot approve another host.

## Identity, retries, and conflicts

Records have random, immutable IDs distinct from names and principal domains.
The host also keeps a random 256-bit enrollment credential in `enrollment.key`
beside its principal-domain file, with mode 0600. This is a bearer credential over
TLS, not a new SSH signing key. Inventory stores only its hash. Retrying with that
credential returns the existing pending or approved registration, without
replacing its attributes or consuming another token. It also makes a lost token
redemption response safely retryable. Do not clone that credential into another
machine image.

Pending proposals may overlap each other. A new submission cannot overlap an
already approved dynamic host or an exact static record. Approval rechecks
uniqueness while holding the same lock as its write. Conflicts must be resolved by
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

`inventory.state-dir` contains `inventory.yaml` and `inventory.lock`. The YAML
snapshot contains versioned host records, token metadata/hashes, retired-name
tombstones, and an audit of committed mutations. One inventory process owns the
store at a time through an OS file lock. The directory is created with mode 0700
and snapshots with mode 0600. Use a local filesystem; this is not an HA/NFS design.

Mutations copy the committed state, validate it, write and sync a temporary file,
rename it over the snapshot, and sync the directory on Unix. Host activation,
token consumption, and the audit event commit together. A storage failure disables
further managed reads and writes until repair/restart; static exact records still
resolve. If the directory can be locked but its snapshot is corrupt at startup,
the service logs the failure and serves static exact records while managed
operations return unavailable. Failure to establish the directory/lock still
prevents startup. The code has Windows locking support, but Windows cannot provide
the same directory-fsync step through Go's file API.

Reads use committed in-memory snapshots with a content revision. Mutations are
visible to subsequent reads immediately. A read already in flight may complete
using its earlier snapshot; removal is not synchronous certificate revocation.

For experimentation: **stop inventory before manually editing `inventory.yaml`**,
keep a backup, and restart afterward. Live file edits are not watched and will be
overwritten by the next API mutation. Preserve IDs, credential hashes, token use
metadata, and retired-name tombstones unless deliberately resetting that state.
A restored older backup can resurrect old approvals or unused tokens; recovery
must account for that. Static YAML and role changes also require restart.

The whole snapshot, including audit, is rewritten per mutation. This favors easy
inspection and iteration over large fleets. There is no compaction, pagination,
SCIM, database backend, multi-writer coordination, or configurable RBAC yet.

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
credentials. Enrollment uses its host credential and optional one-use token.
The broker sends admin requests to the CA-advertised endpoint itself, so neither
an admin CLI destination override nor a local response exposes the OIDC token.
A 401 triggers one broker refresh/retry; permission denials do not.

## Validation

Tests cover durable restart, locking, stale edits, concurrent approvals and token
redemption, token expiry/revocation/retries, static precedence, wildcard tombstones,
corruption recovery, immutable snapshots, actual configured OIDC claim mapping,
active users and group grants, cross-origin discovery and redirect refusal,
editor cancellation/retry, and local sshd setup ordering. A combined-server test
runs real admin CLI commands through an agent and verifies that issuance is denied
while pending, allowed after approval, and denied after removal.
