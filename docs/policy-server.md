# Writ policy guide

This guide explains how to set up and use epithet's in-process Writ evaluator with CA-authenticated users.

Directory and inventory run as separate fact services; see the [inventory service guide](inventory.md) for combined deployment, standalone configuration, and migration.

## Overview

The CA makes authorization decisions by evaluating a **writ policy file** against CA-supplied **inventory facts** about users and hosts. Policy rules say who may reach which account on which hosts; the inventory says who the users are (directory records) and what the hosts are (names plus labels).

**Key features:**
- CA handles OIDC validation (Google Workspace, Okta, Azure AD, etc.)
- A readable, order-independent policy language (`.writ`) with explicit `allow`/`deny` rules — deny always wins
- User inventory (groups, userType, department, organization) and labeled host inventory, pluggable behind an interface (static files or a managed SCIM directory)
- Certificates minted per connection, using either compatible account-name principals or destination-bound hashed principals
- Certificate validity clamped to the auth token's remaining lifetime
- `epithet policy --check` validates policy; `epithet inventory --check` validates inventory
- Built-in to the epithet binary (no separate deployment needed)

**Security boundary:** `account-name`, the explicit compatibility mode,
puts the requested account name (for example, `root`) in the SSH certificate.
It does not put the host identity in the credential. A certificate authorized
for `root@dev-1` can therefore authenticate as `root` on `prod-1` while it
remains valid if both hosts trust the same CA. Treat host selectors in this
mode as issuance-time conditions and the effective credential scope as
`account@CA-trust-domain`, not `account@host`.

`epithet-principal-v1` makes issuance destination-bound using the v1 encoding.
The CA derives a versioned principal from the inventory principal domain and
requested account name after policy authorizes the human-readable `account@host`
tuple. An offline
`AuthorizedPrincipalsCommand` on the target derives the same
value from its local domain and account name. It requires no per-account
registry, account synchronization, or online authorization check by sshd.
Static inventory supports both isolated exact hosts and intentionally shared
fleet domains. Authenticated managed registration remains control-plane work
rather than a policy-language feature; routine SSH host-key rotation is
independent.

## Quick start

### 1. Configure the service topology

Follow [combined or separate deployment](inventory.md). Provision distinct CA
and control signing keys, and configure OIDC on CA (and separately deployed
control). Fact services receive only the trusted public keys.

### 2. Write a policy file

Create `~/.epithet/policy.writ`:

```
# ── vocabulary ──────────────────────────────────────────
user sre = group:SRE
user eng = group:Engineering

host prod = {env=prod}
host dev  = {env=dev}

# ── rules ───────────────────────────────────────────────
allow $sre -> ubuntu@$prod
allow $sre -> root@$prod, ttl 2m, label "sre-prod-root"
allow $eng -> *@$dev
deny  userType:contractor -> *@$prod, label "no-contractors-in-prod"
```

### 3. Write an inventory file

Create `~/.epithet/inventory.yaml`:

```yaml
users:
  - userName: alice@example.com     # readable Writ userName: and audit identity
    id: "example-alice-subject" # replace with verified inventory id
    groups: [SRE]
    userType: employee
  - userName: bob@example.com
    id: "example-bob-subject"
    groups: [Engineering]
    userType: contractor

hosts:
  - names: [prod-db-1]
    labels: {env: prod, role: db}
    accounts: [root, postgres, ubuntu]   # optional: restricts issuable accounts
  - names: [dev-box]
    labels: {env: dev}
  - pattern: "ci-runner-*"               # synthesizes a host for any matching name
    labels: {env: dev, ephemeral: "true"}
```

These example hosts use account-name compatibility. The inventory service now
defaults to destination-bound `epithet-principal-v1`; either set
`principal-mode = "account-name"` explicitly for this example, or enroll
the hosts and record their domains. The check below selects static-only mode so
it validates the YAML without opening managed host storage.

### 4. Validate and start

```sh
epithet policy --check --policy-file ~/.epithet/policy.writ
epithet directory --check --directory-static-file ~/.epithet/inventory.yaml
epithet inventory --check --inventory-mode static --principal-mode account-name --inventory-static-file ~/.epithet/inventory.yaml
epithet --config server.toml server
```

Configure `policy-file` in `toml`. Writ runs inside CA; there is no policy
service to start. Every certificate carries exactly one principal for the requested
connection, never the union of accounts the user could access. Destination binding
requires `epithet-principal-v1` and a target configured to validate that principal.

## The writ policy language

A policy file is a sequence of macro definitions and rules. A rule has a punctuation **head** — who `->` account `@` where — and an optional keyword **tail** of comma-separated clauses:

```
allow <users> -> <accounts>@<hosts>, <clauses...>
deny  <users> -> <accounts>@<hosts>, <clauses...>
```

Evaluation is **order-independent**: file order never matters, and any matching `deny` always wins over any `allow`.

### Matchers

| Position | Matchers |
|---|---|
| users | `userName:"alice@example.com"`, `group:SRE`, `userType:employee`, `department:Platform`, `organization:Acme`, `*` |
| accounts | a name (`root`), a glob (`deploy-*`), `*` |
| hosts | a name (`prod-db-1`), a label-aware glob (`*.example.com`, `**.example.com`), a label selector (`{env=prod, role=db}`), `*` |

- `[]` makes a union: `allow [$sre, $dba] -> [ubuntu, deploy]@$prod`.
- `{}` entries AND: `{env=prod, role=db}` requires both labels.
- Globs match **names, never attribute values** — `group:SRE*` is an error; quote a value containing glob characters (`group:"weird*name"`) to match it literally. Account globs are flat. In host globs, `*` and `?` stay within one dot-delimited label and a whole-label `**` crosses zero or more labels. Thus `*.example.com` matches `a.example.com` but not `a.b.example.com`; `**.example.com` matches both. A standalone `*` remains universal.
- Host patterns deliberately reject character classes, brace alternatives, escapes, `/`, and malformed or embedded `**`. Inventory and Writ use the same hostname-pattern language.
- Host names compare ASCII-case-insensitively (they are lowercased at every boundary); account names, tag values, and labels are byte-exact.

### Macros

Macros bind a name to a match expression of a declared kind, must be defined before use, and compose by union only:

```
user  sre        = group:SRE
host  staging_db = {env=staging, role=db}
account admin    = [root, postgres]

allow $sre -> $admin@$staging_db
```

### Negation

`!` exists only in `deny` heads, applies to a whole position, and is legal in each of the three positions independently:

```
deny !$infra -> *@{env=prod}, label "only-infra-in-prod"
```

`![$a, $b]` means "in neither". A negated allow is a syntax error by design: a negated set grows as the world grows, which is fail-safe on a deny and fail-open on an allow.

### Clauses

| Clause | On | Meaning |
|---|---|---|
| `ttl 2m` | allow | Overrides the default cert TTL for this rule; when several satisfied allows set one, the **minimum** governs |
| `until "2026-08-31T22:00Z"` | allow | Rule stops matching at the given instant (RFC 3339, offset mandatory) |
| `label "name"` | both | Human-readable alias for the rule; cosmetic, shows up in logs and denials |
| `require [oncall, approval]` | allow | Named async facts that must be satisfied |
| `when freeze` | both | Named flags that must currently hold |
| `notify "target"` | both | Fire-and-forget notification |

`require`, `when`, and `notify` name **registered plugins**. The CA evaluator currently registers none, so a policy using any of them fails at startup with an error naming the unknown reference — the seams exist and the plugin mechanism (subprocess handlers) is planned. `ttl`, `until`, and `label` are fully supported.

Cert **extensions** are deliberately not in the language: they are deployment configuration, set with the repeatable `--certificate-extension name=value` flag (default: `permit-pty`, `permit-agent-forwarding`, `permit-user-rc`).

## The inventory

The inventory answers two questions at evaluation time: who is this identity, and what is this host? Users can come from [SCIM provisioning](scim.md) or static YAML, independently of host storage. The static implementation is one or more YAML files served by `epithet inventory --inventory-static-file` (repeatable, globs allowed). Files concatenate; duplicate users or hosts across files are a load error, and unknown fields are an error rather than a silently ignored typo.

### Users

User facts use plain fields for identity, activity, group memberships, and profile attributes. The required `id` is the provider-scoped identifier selected by the identity mode, used both for authentication lookup and Writ `id:` selectors:

```yaml
users:
  - userName: alice@example.com   # matched by Writ userName:; used in cert/audit identity
    id: "example-alice-subject" # required; exact mapped OIDC user ID
    active: true                  # default true; false matches nothing, ever
    groups: [SRE, Engineering]    # matched by group:
    userType: employee            # matched by userType:
    department: Platform          # matched by department:
    organization: Acme            # matched by organization:
```

The CA verifies signature, issuer, audience, expiration, and a nonempty OIDC `sub`. It then resolves the identity using `oidc-identity-mode` and compares that value **byte-for-byte** against inventory `id`. The selected claim must be a nonempty string; missing, null, numeric, object, and array values fail authentication. There is no fallback to another claim, email, or `userName`. Unknown IDs and users with `active: false` are denied structurally. Missing or duplicate IDs, and duplicate `userName` values across files, fail startup and `--check`.

Configure the identity mode on CA and control. `stable-id` is the default; explicitly setting it makes the choice visible:

```toml
oidc-identity-mode = "stable-id"
```

In `stable-id` mode, `user-id-claim` overrides the provider default. For example:

```toml
oidc-client-id = "your-client-id"
oidc-identity-mode = "stable-id"
oidc-issuer = "https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0"
oidc-user-id-claim = "oid"
```

The CLI equivalent is `epithet ca --oidc-user-id-claim oid`. An explicit value overrides the provider default:

| Configured provider | Default claim |
|---|---|
| Google | `sub` |
| Okta | `sub` |
| Microsoft Entra, tenant-specific issuer | `oid` |
| Other OIDC providers | `sub` |

Entra detection uses the configured HTTPS issuer: tenant-specific `/TENANT/v2.0` paths on `login.microsoftonline.com`, `login.microsoftonline.us`, `login.partner.microsoftonline.cn`, or `login.chinacloudapi.cn`, and v1 `sts.windows.net/TENANT/`. Use the exact tenant-specific issuer from discovery, not `common`, `organizations`, or `consumers`. Token issuer verification remains exact; IDs from different tenants are not interchangeable. Microsoft documents the distinction between application-specific `sub` and directory `oid` in its [ID-token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference).

Overrides name a literal top-level claim (including namespaced claim names), not a JSON path or expression. Choose a stable, non-reassignable user identifier when available. Any claim override, including `user-id-claim: email`, is permitted in `stable-id` mode and requires only a nonempty string. An email override does **not** check `email_verified`; the administrator owns that trust decision. Groups and profile attributes still come from inventory. The original OIDC subject remains separate from the mapped ID.

For address-based inventory with enforced email verification, select `verified-email`:

```toml
oidc-identity-mode = "verified-email"
```

```yaml
users:
  - id: suzie@example.com
    userName: suzie
    groups: [Engineering]
```

This mode always uses the token's nonempty `email` string and requires `email_verified` to be the JSON boolean `true`. Missing, false, null, or other types (including the string `"true"`) fail authentication. Do not configure `user-id-claim` in this mode; conflicting settings and unknown modes fail startup and `--check`. The CLI equivalent is `--oidc-identity-mode verified-email`.

Email matching is byte-for-byte: there is no case folding, whitespace trimming, alias resolution, or domain inference. Verification is an assertion from the configured issuer that the address was verified, not a promise of perpetual ownership or organization membership. Addresses can change or be reassigned; email-based grants follow the configured address. Switching modes or claims requires reviewing inventory IDs and affected Writ `id:` selectors. The mode names retain their semantics independently of any future change to the default.

`userName` remains an administrator-controlled, readable name for Writ's `userName:` selector and certificate/audit identity. A token's email change does not rename it. An intentional inventory rename changes which `userName:` rules match; group and attribute selectors continue to evaluate the same user's configured attributes.

Writ `id:"provider-user-id"` matches the same `id` supplied in static YAML. In stable-ID deployments, keep it stable across `userName` renames and never reuse it for replacement users. Static inventory supplies the internal schema directly. In SCIM mode, inventory maps user `externalId` to this normalized `id`; the server-issued SCIM resource `id` is separate. Group names are persistent inventory-owned bindings. See [SCIM provisioning](scim.md).

**Writ selector migration (breaking, pre-1.0):** Use the SCIM field names
for scalar selectors; keep `group:` singular for a membership test. Replace the previous shorthand as follows:

| Previous selector | Current selector |
|---|---|
| `username:` (or the original name-based `id:`) | `userName:` |
| `uid:` | `id:` |
| `type:` | `userType:` |
| `dept:` | `department:` |
| `org:` | `organization:` |

For example:

```writ
allow userName:"alice@example.com" -> root@*
allow group:Admins -> root@*
```

Apply the changes in macros and deny rules too. **`id:` now exclusively
matches an immutable inventory resource ID.** It no longer matches a
username, and no language-version declaration is required. The other old
shorthands are rejected. Name reuse deliberately transfers `userName:`
matches to the new holder.

Scalar selectors use the user fact field names, with Writ matching semantics.
The singular `group:` tests one membership in the plural inventory `groups`
field; `groups:` is not a selector. The `department:` and
`organization:` selectors refer to plain user fields. Writ does not
parse arbitrary SCIM filters or JSON paths.

Replace the old static `subject` (or `oidc-subject`) key with `id`. The old keys are rejected, including when `id` is also present. For the `sub` mapping, retain the value. For Entra's default `oid` mapping or an explicit override, obtain the newly selected identifier; do not merely rename the key and assume the old subject is correct.

The compiler emits IL schema 2; evaluators reject schema 1 and obsolete
matcher names. Recompile stored policies and update external references
to rule content IDs, which change when matcher names change. Validate the
policy and inventory with `epithet policy --check` before restarting with
the new binary.

All inventory files share the CA's configured provider/tenant scope. Changing issuer or the selected claim requires deliberately reviewing every ID binding. Matching strings from different providers do not establish the same person. There is no automatic enrollment or provider migration.

### Migrating from email lookup

This is a breaking inventory change. Start the new agent with your existing client configuration, then ask that running agent for its identity:

```sh
epithet agent                         # runs in the foreground
# In another terminal:
epithet agent identity
# Or, for a named running profile:
epithet agent --agent-name work identity
```

`agent identity` inherits the normal `agent-name` profile selection; `--broker-socket /path/to/broker.sock` selects an explicit socket. It uses the running agent's issuer and audience configuration. Inventory identity mapping stays on the inventory service. It reuses valid authentication, refreshes when necessary, or prompts for browser login through the same authentication flow as SSH. Login progress goes to stderr; stdout defaults to tab-delimited field/value rows:

```text
issuer	https://issuer.example
subject	oidc-subject
email	alice@example.com
email_verified	true
```

Use `epithet agent identity --json` (or `-j`) for JSON output:

```json
{"issuer":"https://issuer.example","subject":"oidc-subject","email":"alice@example.com","email_verified":true}
```

The agent verifies the token before returning these claims. It reports issuer and subject, plus `oid`, `email`, and `email_verified` when present with the expected types. A false verification value is shown as false; missing or malformed optional claims are omitted. No mapped inventory `id` is returned. The command does not request a certificate or need an inventory entry, and bearer tokens, refresh tokens, and client secrets remain inside the agent.

Confirm the issuer and signed-in account, then use the field appropriate to your inventory configuration: `subject` for the default `sub` mapping, `oid` for Entra's default, or `email` for verified-email mode. The command describes only the current user, does not establish policy acceptance, and does not display arbitrary custom ID claims. Keep the intended inventory `userName` and groups. Migrate old name-based Writ `id:` rules to `userName:` as described above.

The former standalone `epithet identity` command is removed. Start the agent first and restart existing agents after upgrading to get the new diagnostic output. Changes to identity modes or claim mapping require restarting CA and policy; the agent does not consume these settings.

Prepare the inventory separately, then validate it with the new binary and existing policy:

```sh
epithet policy --check --policy-file /path/to/policy.writ
epithet inventory --check --inventory-static-file /path/to/updated-inventory.yaml
```

Include your configured `--principal-mode` if hosts inherit a nondefault mode. Install the new binary and updated inventory together, restart the policy service (or combined server), and verify a fresh issuance. Older binaries reject the new inventory field; newer binaries reject the old unbound user records. Keep a working administrative SSH session during the switch. A cached certificate does not test the new binding: use a fresh agent profile or evict the relevant certificate before checking issuance.

### Hosts

```yaml
domains:
  - ci-runners

hosts:
  - names: [prod-db-1, prod-db-1.internal] # one host, equivalent DNS names
    labels: {env: prod, role: db}
    accounts: [root, postgres]    # optional account grounding — see below
    principal-mode: epithet-principal-v1
    domain: "epithet-host-id-v1:..." # generated by epithet host enroll
  - pattern: "ci-runner-*.internal" # pattern entry: shared host glob
    labels: {env: ci}
    principal-mode: epithet-principal-v1
    domain: ci-runners
```

A connection's host must resolve in the inventory or the request is denied — this is what makes label selectors trustworthy. Two entry forms:

- **Exact entries** (`names:`) are individual hosts with one or more equivalent DNS names, looked up first. Use either `names` or `pattern`; they cannot be combined. Names are normalized with ASCII case folding and must be nonempty and unique across all host records and files.
- **Pattern entries** (`pattern:`) resolve any requested name they match. They use the same label-aware hostname globs as Writ host selectors. They adopt the requested name, independent of principal mode or domain. Patterns are the escape hatch for short-lived fleets (VM pools, CI runners) that follow a naming pattern but cannot be enumerated. Patterns match in file order; first match wins.

An exact hostname matcher or glob matches if it matches **any** name of the
resolved host. A deny matching one name therefore applies through every other
name. Negation means no registered name matches that matcher, rather than
finding a different name that does not match. Labels, accounts, and principal
metadata belong to the host record and are shared by all its names.

`domains` declares the human-readable authorization domains that host entries
may reference. The loader rejects misspelled or otherwise undeclared names.
Here and below, `domain` means **principal domain**, an SSH authorization
boundary. It is independent of DNS domains and is never inferred from a DNS suffix.
Generated per-host domains use the reserved `epithet-host-id-v1:` namespace
and are carried directly by their exact host entry rather than declared.

`principal-mode` overrides the deployment default for an exact host or
pattern. Every entry whose effective mode is `epithet-principal-v1` must have a
canonical `domain` matching the literal value stored on its target hosts.
Patterns may use a declared named domain, allowing an ephemeral fleet to use
destination-bound principals without enumerating every member. Patterns may
not use generated per-host domains. Exact entries win before patterns;
otherwise the first matching pattern wins.

Every host accepting one domain derives the same principal for a given
account. Put only hosts that should accept interchangeable account credentials
in one domain: a certificate issued for one member can be accepted by another.
Static inventory requires every entry sharing a named domain to have identical
labels and account grounding. Issuance policy still evaluates the requested
host's names, labels, and account restrictions; the principal domain is opaque
to Writ and never substitutes for a hostname.

**Account grounding:** if a host entry lists `accounts`, certificates are only issuable for accounts in that list — even a policy `*` cannot reach an unlisted account. If the entry has no `accounts` key, account matching is ungrounded and rules match against the requested account name directly.

## Configuration

The flat TOML file supplies Writ and authentication settings to CA:

```toml
certificate-default-ttl = "5m"
oidc-client-id = "epithet"
oidc-identity-mode = "stable-id"
oidc-issuer = "https://identity.example.com"
policy-file = "/etc/epithet/policy.writ"
```

`policy-file` is required. `certificate-default-ttl` defaults to five minutes and is
further bounded by login expiry. `certificate-extension` configures certificate extensions.
OIDC audience checking requires `oidc-client-id`. `oidc-identity-mode` and `oidc-user-id-claim`
can also be supplied by `EPITHET_OIDC_IDENTITY_MODE` and
`EPITHET_OIDC_USER_ID_CLAIM`; flags override files, which override environment.

Directory owns user source selection; inventory owns host source selection and
`principal-mode`. Static inventory defaults to `epithet-principal-v1`; individual
hosts can override it. `principal-mode` overrides the combined inventory
child setting. See [deployment configuration and migration](inventory.md).

Policy and static facts are loaded at startup. Restart their owning processes to
reload them. `epithet policy --check` validates policy offline, including plugin
references; `epithet directory --check` and `epithet inventory --check` validate
their respective data stores.

## Authorization logic

For each request `(identity, account@host)` the evaluator (`pkg/policyserver/writpolicy` over `pkg/writ/eval`):

1. **Validates the OIDC token** — signature against the provider's JWKS, expiry, issuer, audience — and extracts the identity and token expiry.
2. **Structural gates** — the identity must resolve to an `active` inventory user; the host must resolve in the inventory; if the host lists accounts, the requested account must be among them. Any failure → 403, regardless of policy text.
3. **Collects matching rules** — a rule matches when its user, account, and host expressions all match.
4. **Deny wins** — any matching deny → 403, always; no allow can override. The private denial names the rule's label (or content id); the public CA response is only `access denied`.
5. **Authorizes issuance** if any allow survives: the response `ttlSeconds` is the whole-second value of the minimum `ttl` among satisfied allows (else the default), and `extensions` are the deployment set. Built-in Writ policy returns the authentication expiry from inventory as `notAfter`. CA constructs the certificate Key ID and exactly one requested principal and applies the returned TTL and deadline; Writ `until` continues to control rule eligibility at evaluation time.

Evaluator or inventory failures fail **closed** (500), never "treat as no match".

## Target host configuration

### Host enrollment

Install the same Epithet binary on the target, then bootstrap its domain and
CA trust anchor from the CA URL:

```console
$ sudo epithet host enroll --ca https://epithet.example.com/
epithet-host-id-v1:...
```

The command validates the CA response before changing local state and will not
replace a different existing CA key. When managed inventory is advertised, it
prepares the domain and host proposal in memory and opens the proposal for review.
Cancellation leaves persistent state unchanged. After review, it installs the
local identity and trust files. It then validates the existing sshd
configuration, validates a complete candidate configuration, installs a
managed fragment, validates the installed configuration, and reloads sshd. If
installation or reload fails, it restores the previous configuration. It is
safe to rerun for local setup and does not install a persistent Epithet process.
Managed enrollment submits a fresh proposal on every run, after local setup
completes; pending admission needs no further host setup after approval. The managed
fragment records the selected principal mode and the absolute domain and CA-key
paths, so a later CA-URL-only rerun recovers nondefault state paths before it
touches host state. If the main sshd configuration itself is nonstandard,
repeat `--sshd-config-file` so enrollment can find that managed fragment.

On Linux the default state files are `/var/lib/epithet/domain` and
`/var/lib/epithet/epithet-ca.pub`; the native state directory is
`/var/db/epithet` on the BSDs, `/var/opt/epithet` on Solaris, illumos, and AIX,
`/Library/Application Support/Epithet` on macOS, and `%ProgramData%\Epithet`
on Windows. Use `--principal-domain-file` and `--ca-public-key-file` during enrollment to
select another layout or to support an otherwise unknown platform.

The sshd defaults use `/etc/ssh/sshd_config` and
`/etc/ssh/sshd_config.d/60-epithet.conf` on Unix-like systems, and the OpenSSH
directory beneath `%ProgramData%` on Windows. Enrollment uses an existing global
`Include` that covers the fragment, including wildcard and nested includes. If
none covers it, enrollment adds an explicit include for that file only; it does
not enable the entire drop-in directory. Rerunning enrollment removes a redundant
Epithet-managed include when another global include covers the fragment. The
fragment keeps its `60-epithet.conf` name and the host's existing include order.
Before reloading, enrollment checks the effective global Epithet settings with
`sshd -T`; conflicting earlier settings cause an error and restoration of the
previous configuration.

The command reloads through the native service manager (`systemctl`/`service`,
BSD rc, `launchctl`, SMF, AIX SRC, or PowerShell). Use `--sshd-config-file`, `--sshd-fragment-file`,
`--sshd-binary`, or `--epithet-binary` to select nonstandard installation paths.

The printed domain is the value to put in this host's static-inventory entry.
Enrollment defaults to `epithet-principal-v1` on Unix-like hosts; pass
`--principal-mode account-name` for a compatibility host. The selection must
match the mode inventory resolves for that inventory entry. Windows
defaults to `account-name` because its in-box OpenSSH does not support
`AuthorizedPrincipalsCommand`; destination-bound mode is rejected there.

For a static fleet, provision the declared name as the only line of the domain
file before running enrollment. Enrollment validates and preserves an existing
canonical value, so every fleet image may contain the same domain. Static
inventory validates that the pattern references a declared name. Managed
`--domain NAME` lookup and admission require the separately tracked inventory
enrollment service; the current local/static command deliberately does not
accept an unchecked domain flag.

### Destination-bound hashed principals

The managed fragment for destination-bound mode contains the following
configuration. The authorized-principals command is entirely local: it hashes
the canonical domain and the account supplied as `%u`, then prints the one
principal sshd should accept.

```ssh_config
TrustedUserCAKeys /var/lib/epithet/epithet-ca.pub
AuthorizedPrincipalsCommand /usr/local/bin/epithet host authorized-principals --principal-domain-file /var/lib/epithet/domain %u
AuthorizedPrincipalsCommandUser nobody
```

Enrollment verifies that the binary, domain file, CA key, and their parent
directories remain root-controlled, and that the configured command user can
execute the binary and read the domain file through every parent directory.
The domain is not secret, but only root should be able to change it. Put the
exact `epithet-host-id-v1:...` text printed by ordinary enrollment in the
matching inventory entry's `domain`.

The domain is independent of SSH transport keys, so routine host-key rotation
does not change principals. Changing the domain changes the SSH authorization
boundary. The helper emits only the principal derived from that domain and
account.

The v1 derivation is public in `pkg/principal`: SHA-256 over three RFC 4251 SSH
strings — `epithet-principal-v1`, the canonical domain text, and the byte-exact
account name — rendered as `epithet-principal-v1-` plus unpadded
base64url. See the [principal protocol](./principals.md) for the normative byte
encoding and test vector. A bespoke inventory can supply this principal mode and
the same on-host helper.

Deleting and recreating an account with the same name in the same domain
preserves its derived principal. Any exposure from a previously issued
certificate remains bounded by that certificate's lifetime.

### Account-name compatibility

The compatibility mode names the SSH username the client requested
as the certificate's sole principal. sshd's default principal matching is
therefore enough, and no `AuthorizedPrincipalsFile` mapping is required.

Enroll the host in compatibility mode:

```console
$ sudo epithet host enroll --ca https://epithet.example.com/ --principal-mode account-name
epithet-host-id-v1:...
```

Its managed sshd fragment only needs the trust anchor:

```ssh_config
# Trust the epithet CA
TrustedUserCAKeys /var/lib/epithet/epithet-ca.pub
```

With only `TrustedUserCAKeys` set, sshd's default behavior is to
accept a certificate for login as user `X` when the certificate names `X` as
a principal - which is exactly what the CA issues, since account
expressions in rules match the real login usernames.

This configuration is simple but is explicitly **not destination-bound**.
Every host in the CA trust domain that has an account named `X` may accept the
same still-valid certificate. Put hosts with different security boundaries
under separate CAs if they cannot use hashed principals. Merely configuring an
authorized-principals source that returns the same account-name principal does
not fix the problem: the accepted principal must incorporate the designated
principal domain.

See [OIDC setup guide](./oidc-setup.md) for provider-specific configuration (Google, Okta, Azure AD).

## Deployment patterns

Supervise `epithet server` for a combined deployment, or supervise CA, control,
directory, and inventory independently. See [deployment configuration](inventory.md).
There is no separate policy process. Validate before restarting:

```sh
epithet policy --check --policy-file /etc/epithet/policy.writ
epithet directory --check
epithet inventory --check
```

## Troubleshooting

### Common errors

The detailed policy messages below are private diagnostics found in server
logs. Public CA denials say only `access denied`; pending decisions say
`authorization pending; try again later`. See [public CA errors](ca-errors.md).

**"user does not resolve to an active inventory user" (403)**
- The configured OIDC user-ID claim doesn't match any inventory `id` (byte-for-byte, case-sensitive), or the record has `active: false`
- Verify the OIDC provider is sending the expected claim

**"host is not in inventory" (403)**
- The connection's host name matches no exact inventory entry and no pattern entry
- Remember host names are lowercased; `*` and `?` stay within one label and a whole-label `**` crosses labels

**"denied by rule ..." (403)**
- A `deny` rule matched; the message names its label or content id

**"no policy rule allows this access" (403)**
- No `allow` rule matched the (user, account, host) tuple

**"policy references unknown requirement/flag/notify target" (at startup)**
- The policy uses `require`, `when`, or `notify` but no plugin with that name is registered — the static server currently registers none

**"Invalid token" (401)**
- Inventory rejected the user JWT: signature verification failed, token expired, or issuer/audience mismatch
- Check system clock synchronization

**"request verification failed" (private policy 401; public CA 502)**
- The CA's service JWT failed verification: expired (>60s old), wrong `aud`, body-hash mismatch, method/target mismatch, or the wrong signing key
- Check that `ca-public-key` in the config matches the CA's actual public key

### Debugging

Enable verbose logging:

```bash
epithet -vv policy
```

## Evaluation boundary

CA performs OIDC validation and independent fact lookups before invoking Writ
in-process. Writ receives authenticated ID and expiry, optional user attributes,
all host names, labels, and account restrictions. It does not receive principal
domains, source revisions, or bearer tokens.

Bespoke integrations implement the [directory or inventory fact API](fact-services.md),
not the retired policy HTTP API. CA retains the policy decision and signing boundary
inside one process, and exposes only its existing certificate API publicly.

## See also

- [OIDC setup guide](./oidc-setup.md) - Provider configuration
- [Architecture](./architecture.md) - How epithet works
- [Example configurations](../examples/policy-server/) - Deployment examples
