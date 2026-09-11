# Policy server guide

This guide explains how to set up and use epithet's built-in policy server with inventory-authenticated users.

Inventory runs in a separate service; see the [inventory service guide](inventory.md) for combined deployment, standalone configuration, and migration.

## Overview

The epithet policy server makes authorization decisions by evaluating a **writ policy file** against CA-supplied **inventory facts** about users and hosts. Policy rules say who may reach which account on which hosts; the inventory says who the users are (directory records) and what the hosts are (names plus labels).

**Key features:**
- Inventory handles OIDC validation (Google Workspace, Okta, Azure AD, etc.)
- A readable, order-independent policy language (`.writ`) with explicit `allow`/`deny` rules — deny always wins
- User inventory (groups, userType, department, organization) and labeled host inventory, pluggable behind an interface (static files today)
- Certificates minted per connection, using either compatible account-name principals or destination-bound hashed principals
- Certificate validity clamped to the auth token's remaining lifetime
- `epithet policy --check` validates policy; `epithet inventory --check` validates inventory
- Built-in to the epithet binary (no separate deployment needed)

**Security boundary:** `account-name`, the compatibility default,
puts the requested account name (for example, `root`) in the SSH certificate.
It does not put the host identity in the credential. A certificate authorized
for `root@dev-1` can therefore authenticate as `root` on `prod-1` while it
remains valid if both hosts trust the same CA. Treat host selectors in this
mode as issuance-time conditions and the effective credential scope as
`account@CA-trust-domain`, not `account@host`.

`epithet-principal-v1` makes issuance destination-bound using the v1 encoding.
The CA derives a versioned principal from the inventory principal domain and
requested account name after policy authorizes the human-readable `account@host`
tuple (or `account@domain` for a shared named domain). An offline
`AuthorizedPrincipalsCommand` on the target derives the same
value from its local domain and account name. It requires no per-account
registry, account synchronization, or online authorization check by sshd.
Static inventory supports both isolated exact hosts and intentionally shared
fleet domains. Authenticated managed registration remains control-plane work
rather than a policy-language feature; routine SSH host-key rotation is
independent.

## Quick start

### 1. Get the CA public key

The policy server needs your CA's public key to verify the CA-minted service JWT on every request (see [Service authentication](#service-authentication-ca--policy-server) below):

```bash
# If running the CA server locally
curl http://localhost:8080/

# Or extract from a file
cat ~/.epithet/ca_key.pub
```

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
  - name: prod-db-1
    labels: {env: prod, role: db}
    accounts: [root, postgres, ubuntu]   # optional: restricts issuable accounts
  - name: dev-box
    labels: {env: dev}
  - pattern: "ci-runner-*"               # synthesizes a host for any matching name
    labels: {env: dev, ephemeral: "true"}
```

### 4. Check and start the policy server

```bash
# Validate without starting a server
epithet policy --check --policy-file ~/.epithet/policy.writ
epithet inventory --check --static ~/.epithet/inventory.yaml

# Start (flags may instead come from the policy: config section)
epithet policy \
  --policy-file ~/.epithet/policy.writ \
  --ca-pubkey "$(curl -s http://localhost:8080/)" \
  --listen 0.0.0.0:9999
```

**Important:** Each issued certificate carries exactly one principal for the
requested connection, never the union of every account the user could reach.
A certificate is minted fresh for every connection past the broker's local
cache of still-valid agents. Destination binding only applies when the
resolved host's effective mode is `epithet-principal-v1` and the target is
configured to validate the derived principal.

Start inventory with the OIDC configuration in the [inventory service guide](inventory.md).

### 5. Configure the CA to use the policy server

```bash
epithet ca \
  --key ~/.epithet/ca_key \
  --policy http://localhost:9999 \
  --listen :8080
```

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

`require`, `when`, and `notify` name **registered plugins**. The static policy server currently registers none, so a policy using any of them fails at startup with an error naming the unknown reference — the seams exist and the plugin mechanism (subprocess handlers) is planned. `ttl`, `until`, and `label` are fully supported.

Cert **extensions** are deliberately not in the language: they are deployment configuration, set with the repeatable `--extension name=value` flag (default: `permit-pty`, `permit-agent-forwarding`, `permit-user-rc`).

## The inventory

The inventory answers two questions at evaluation time: who is this identity, and what is this host? It is pluggable by design (databases are the expected future); the built-in implementation is one or more static YAML files served by `epithet inventory --static` (repeatable, globs allowed). Files concatenate; duplicate users or hosts across files are a load error, and unknown fields are an error rather than a silently ignored typo.

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

The inventory service verifies signature, issuer, audience, expiration, and a nonempty OIDC `sub`. It then resolves the identity using `inventory.oidc.identity-mode` and compares that value **byte-for-byte** against inventory `id`. The selected claim must be a nonempty string; missing, null, numeric, object, and array values fail authentication. There is no fallback to another claim, email, or `userName`. Unknown IDs and users with `active: false` are denied structurally. Missing or duplicate IDs, and duplicate `userName` values across files, fail startup and `--check`.

Configure the identity mode once on the inventory service. `stable-id` is the default; explicitly setting it makes the choice visible:

```yaml
inventory:
  oidc:
    identity-mode: stable-id
```

In `stable-id` mode, `user-id-claim` overrides the provider default. For example:

```yaml
inventory:
  oidc:
    issuer: "https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0"
    client-id: "your-client-id"
    identity-mode: stable-id
    user-id-claim: oid
```

The CLI equivalent is `epithet inventory --oidc-user-id-claim oid`. An explicit value overrides the provider default:

| Configured provider | Default claim |
|---|---|
| Google | `sub` |
| Okta | `sub` |
| Microsoft Entra, tenant-specific issuer | `oid` |
| Other OIDC providers | `sub` |

Entra detection uses the configured HTTPS issuer: tenant-specific `/TENANT/v2.0` paths on `login.microsoftonline.com`, `login.microsoftonline.us`, `login.partner.microsoftonline.cn`, or `login.chinacloudapi.cn`, and v1 `sts.windows.net/TENANT/`. Use the exact tenant-specific issuer from discovery, not `common`, `organizations`, or `consumers`. Token issuer verification remains exact; IDs from different tenants are not interchangeable. Microsoft documents the distinction between application-specific `sub` and directory `oid` in its [ID-token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference).

Overrides name a literal top-level claim (including namespaced claim names), not a JSON path or expression. Choose a stable, non-reassignable user identifier when available. Any claim override, including `user-id-claim: email`, is permitted in `stable-id` mode and requires only a nonempty string. An email override does **not** check `email_verified`; the administrator owns that trust decision. Groups and profile attributes still come from inventory. The original OIDC subject remains separate from the mapped ID.

For address-based inventory with enforced email verification, select `verified-email`:

```yaml
inventory:
  oidc:
    identity-mode: verified-email
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

Writ `id:"provider-user-id"` matches the same `id` supplied in static YAML. In stable-ID deployments, keep it stable across `userName` renames and never reuse it for replacement users. Static inventory supplies the internal schema directly; future provisioning adapters will map provider fields into it. SCIM provisioning and its field mapping are not yet implemented.

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

All inventory files share the policy server's configured provider/tenant scope. Changing issuer or the selected claim requires deliberately reviewing every ID binding. Matching strings from different providers do not establish the same person. There is no automatic enrollment or provider migration.

### Migrating from email lookup

This is a breaking inventory change. Start the new agent with your existing client configuration, then ask that running agent for its identity:

```sh
epithet agent                         # runs in the foreground
# In another terminal:
epithet agent identity
# Or, for a named running profile:
epithet agent --name work identity
```

`agent identity` inherits the normal `agent.name` profile selection; `--broker /path/to/broker.sock` selects an explicit socket. It uses the running agent's issuer and audience configuration. Inventory identity mapping stays on the inventory service. It reuses valid authentication, refreshes when necessary, or prompts for browser login through the same authentication flow as SSH. Login progress goes to stderr; stdout defaults to tab-delimited field/value rows:

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
epithet inventory --check --static /path/to/updated-inventory.yaml
```

Include your configured `--principal-mode` if hosts inherit a nondefault mode. Install the new binary and updated inventory together, restart the policy service (or combined server), and verify a fresh issuance. Older binaries reject the new inventory field; newer binaries reject the old unbound user records. Keep a working administrative SSH session during the switch. A cached certificate does not test the new binding: use a fresh agent profile or evict the relevant certificate before checking issuance.

### Hosts

```yaml
domains:
  - ci-runners

hosts:
  - name: prod-db-1               # exact entry (name is lowercased at load)
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

- **Exact entries** (`name:`) are individual hosts, looked up first.
- **Pattern entries** (`pattern:`) resolve any requested name they match. They use the same label-aware hostname globs as Writ host selectors. In account-name mode they adopt the requested name. A destination-bound named domain exposes the domain name to Writ instead, because the resulting certificate is valid throughout that domain. Patterns are the escape hatch for short-lived fleets (VM pools, CI runners) that follow a naming pattern but cannot be enumerated. Patterns match in file order; first match wins.

`domains` declares the human-readable authorization domains that host entries
may reference. The loader rejects misspelled or otherwise undeclared names.
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
account. That is intentional for aliases and fleets, but it also means policy
authorization cannot honestly be narrower than the domain. Put only hosts
that should accept interchangeable account credentials in one domain. Static
inventory requires every entry sharing a named domain to have identical labels
and account grounding, and Writ matches the domain name rather than an
individual member hostname.

**Account grounding:** if a host entry lists `accounts`, certificates are only issuable for accounts in that list — even a policy `*` cannot reach an unlisted account. If the entry has no `accounts` key, account matching is ungrounded and rules match against the requested account name directly.

## Configuration

Policy and inventory settings can live under the `policy:` and `inventory:` sections of `/etc/epithet/*.yaml` or `~/.epithet/*.yaml` (or a file given with `--config`). Keys use the CLI flag names verbatim (kebab-case):

```yaml
policy:
  listen: "0.0.0.0:9999"
  ca-pubkey: "ssh-ed25519 AAAA..."
  policy-file: /etc/epithet/policy.writ
  default-expiration: 5m
inventory:
  ca-pubkey: "ssh-ed25519 AAAA..."
  oidc:
    issuer: "https://accounts.google.com"
    client-id: "your-client-id"
    identity-mode: stable-id  # or verified-email
    # user-id-claim: sub  # stable-id override; Entra defaults to oid
  static:
    - /etc/epithet/inventory.yaml
  principal-mode: epithet-principal-v1
```

- **`listen`** (optional): address to listen on (default `0.0.0.0:9999`). A `unix:///path/to/policy.sock` value listens on a Unix domain socket; this is how `epithet server` wires its subprocesses together.
- **`ca-pubkey`** (required): the CA's SSH public key (URL, file path, or literal), used to verify the CA's service JWT.
- **`inventory.oidc`** (inventory service, required): `issuer` and `client-id` — `client-id` is required so audience checking can never be silently skipped.
- **`inventory.oidc.identity-mode`** (inventory service, optional): `stable-id` (default) or `verified-email`, as described under [Users](#users). CLI: `--oidc-identity-mode`; environment: `EPITHET_INVENTORY_OIDC_IDENTITY_MODE`.
- **`inventory.oidc.user-id-claim`** (inventory service, optional): top-level claim mapped to inventory `id` in `stable-id` mode; overrides the provider default. Even `email` is allowed without checking verification. CLI: `--oidc-user-id-claim`; environment: `EPITHET_INVENTORY_OIDC_USER_ID_CLAIM`. Flags override file configuration; environment variables supply defaults when the file omits a setting.
- **`policy-file`** (required): the writ policy file.
- **`inventory.static`** (inventory service): inventory file paths or globs.
- **`inventory.principal-mode`** (inventory service): deployment default, either `account-name` (the compatibility default) or `epithet-principal-v1`. A host entry's `principal-mode` overrides it. Naming the concrete protocol version allows different hosts to remain on v1 or move to a future version independently during rollout.
- **`default-expiration`** (optional): cert TTL when no satisfied rule sets a `ttl` (default `5m`). Always further clamped to the auth token's remaining lifetime.
- **`extension`** (flag only): repeatable `name=value` cert extensions.

When using `epithet server`, `inventory.principal-mode` also supplies the default
for the inventory subprocess. An explicitly configured `server.principal-mode`
overrides it, and `epithet server --principal-mode ...` overrides both config
settings. If none is set, the inventory default remains `account-name`.

Policy and inventory are read by their respective services once at startup; restart the relevant service to pick up changes. `epithet inventory --check` validates inventory, and `epithet policy --check` validates policy (parse and compile errors with positions, unknown require/when/notify references, warnings such as unused macros or already-expired `until` rules) and exits non-zero on errors.

## Authorization logic

For each request `(identity, account@host)` the evaluator (`pkg/policyserver/writpolicy` over `pkg/writ/eval`):

1. **Validates the OIDC token** — signature against the provider's JWKS, expiry, issuer, audience — and extracts the identity and token expiry.
2. **Structural gates** — the identity must resolve to an `active` inventory user; the host must resolve in the inventory; if the host lists accounts, the requested account must be among them. Any failure → 403, regardless of policy text.
3. **Collects matching rules** — a rule matches when its user, account, and host expressions all match.
4. **Deny wins** — any matching deny → 403, always; no allow can override. The private denial names the rule's label (or content id); the public CA response is only `access denied`.
5. **Authorizes issuance** if any allow survives: the response `ttlSeconds` is the whole-second value of the minimum `ttl` among satisfied allows (else the default), and `extensions` are the deployment set. CA constructs the certificate Key ID and exactly one requested principal, and independently caps its expiry at the authentication expiry from inventory. Built-in Writ policy supplies no additional absolute deadline; Writ `until` continues to control rule eligibility at evaluation time.

Evaluator or inventory failures fail **closed** (500), never "treat as no match".

## Target host configuration

### Host enrollment

Install the same Epithet binary on the target, then bootstrap its domain and
CA trust anchor from the CA URL:

```console
$ sudo epithet host enroll --ca-url https://epithet.example.com/
epithet-host-id-v1:...
```

The command validates the CA response before changing local state and will not
replace a different existing CA key. It then validates the existing sshd
configuration, validates a complete candidate configuration, installs a
managed fragment, validates the installed configuration, and reloads sshd. If
installation or reload fails, it restores the previous configuration. It is
safe to rerun and does not install a persistent Epithet process. The managed
fragment records the selected principal mode and the absolute domain and CA-key
paths, so a later CA-URL-only rerun recovers nondefault state paths before it
touches host state. If the main sshd configuration itself is nonstandard,
repeat `--sshd-config-file` so enrollment can find that managed fragment.

On Linux the default state files are `/var/lib/epithet/domain` and
`/var/lib/epithet/epithet-ca.pub`; the native state directory is
`/var/db/epithet` on the BSDs, `/var/opt/epithet` on Solaris, illumos, and AIX,
`/Library/Application Support/Epithet` on macOS, and `%ProgramData%\Epithet`
on Windows. Use `--domain-file` and `--ca-pubkey-file` during enrollment to
select another layout or to support an otherwise unknown platform.

The sshd defaults use `/etc/ssh/sshd_config` and
`/etc/ssh/sshd_config.d/60-epithet.conf` on Unix-like systems, and the OpenSSH
directory beneath `%ProgramData%` on Windows. The command reloads through the
native service manager (`systemctl`/`service`, BSD rc, `launchctl`, SMF, AIX
SRC, or PowerShell). Use `--sshd-config-file`, `--sshd-fragment-file`,
`--sshd-binary`, `--epithet-binary`, or `--reload-command` with repeated
`--reload-arg` options for a nonstandard installation.

The printed domain is the value to put in this host's static-inventory entry.
Enrollment defaults to `epithet-principal-v1` on Unix-like hosts; pass
`--principal-mode account-name` for a compatibility host. The selection must
match the mode the policy server resolves for that inventory entry. Windows
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
AuthorizedPrincipalsCommand /usr/local/bin/epithet host authorized-principals --domain-file /var/lib/epithet/domain %u
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
boundary. The temporary `--accept-account-name` option
also emits `%u` for a bounded migration from account-name certificates; while enabled, it restores the
broader `account@CA-trust-domain` acceptance boundary and should not become
permanent.

The v1 derivation is public in `pkg/principal`: SHA-256 over three RFC 4251 SSH
strings — `epithet-principal-v1`, the canonical domain text, and the byte-exact
account name — rendered as `epithet-principal-v1-` plus unpadded
base64url. See the [principal protocol](./principals.md) for the normative byte
encoding and test vector. A bespoke policy server can use this protocol and
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
$ sudo epithet host enroll --ca-url https://epithet.example.com/ --principal-mode account-name
epithet-host-id-v1:...
```

Its managed sshd fragment only needs the trust anchor:

```ssh_config
# Trust the epithet CA
TrustedUserCAKeys /var/lib/epithet/epithet-ca.pub
```

With only `TrustedUserCAKeys` set, sshd's default behavior is to
accept a certificate for login as user `X` when the certificate names `X` as
a principal - which is exactly what the policy server issues, since account
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

### Production setup

For production, run the policy server as a system service:

**systemd unit** (`/etc/systemd/system/epithet-policy.service`):
```ini
[Unit]
Description=Epithet Policy Server
After=network.target

[Service]
Type=simple
User=epithet
Group=epithet
# Config is loaded from /etc/epithet/*.yaml (or specify --config)
ExecStart=/usr/local/bin/epithet policy
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable epithet-policy
sudo systemctl start epithet-policy
```

Validate config changes before restarting:
```bash
epithet policy --check --policy-file /etc/epithet/policy.writ
epithet inventory --check --static /etc/epithet/inventory.yaml
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
- Check that `ca-pubkey` in the config matches the CA's actual public key

### Debugging

Enable verbose logging:

```bash
epithet -vv policy
```

## Policy server HTTP API

The CA server communicates with the policy server over HTTP. This section documents the API contract for implementing custom policy servers.

### HTTP endpoint

`POST /` evaluates a certificate request. It requires a valid CA-minted service
JWT (see [Service authentication](#service-authentication-ca--policy-server)).
Login discovery is served by inventory and forwarded publicly by CA; policy
has no discovery endpoint or OIDC configuration.

### Cert evaluation request format

```
POST /
Authorization: Bearer <service JWT>
Content-Type: application/json
```

```json
{
  "connection": {
    "remoteHost": "server.example.com",
    "remoteUser": "ubuntu",
    "port": 22,
    "proxyJump": "",
    "hash": "a1b2c3d4e5f6"
  },
  "facts": {
    "authentication": {
      "id": "provider-user-id",
      "expiresAt": "2026-09-07T12:05:00Z"
    },
    "target": "server.example.com",
    "user": {
      "id": "provider-user-id",
      "userName": "alice@example.com",
      "active": true,
      "groups": ["engineering"],
      "userType": "employee",
      "department": "Engineering",
      "organization": "Example"
    },
    "host": {
      "name": "server.example.com",
      "labels": {},
      "accounts": [
        "ubuntu"
      ]
    }
  }
}
```

**Fields:**

- `facts` (object, required): normalized policy inputs described below. Inventory transport metadata is not accepted.
- `facts.authentication`: verified `id` and unexpired `expiresAt`. No bearer token or provider settings.
- `facts.target`: the requested hostname, equal to `connection.remoteHost` after ASCII case folding.
- `facts.user`: the user record, whose `id` must match `authentication.id`; explicit `null` means absent.
- `facts.host`: the policy resource (`name`, `labels`, `accounts`); explicit `null` means absent. CA validates inventory's host/domain binding before supplying this resource. A shared domain's resource name can intentionally differ from `target`.

Missing `user` or `host` fields are malformed, while explicit null records produce
structural denial. `host.accounts` is required: null is ungrounded, [] permits no
accounts, and a list restricts available accounts. CA's request-bound signature
covers these facts and the connection. Principal mode/domain, transport version,
and directory/host revisions stay at CA.

- `connection` (object): SSH connection parameters
  - `remoteHost` (string): Target SSH server hostname (OpenSSH `%h`)
  - `remoteUser` (string): Target account name on the remote server (OpenSSH `%r`); CA encodes this account according to the resolved host's principal mode
  - `port` (uint): Target SSH port (OpenSSH `%p`)
  - `proxyJump` (string): ProxyJump configuration (OpenSSH `%j`), empty if not used
  - `hash` (string): OpenSSH `%C` hash - unique identifier for this connection

Request and response bodies are capped at 64 KiB (`wire.MaxBodySize`); an
oversized body gets `413` with a "too large" message rather than a JSON
parse error.

### Response format

**Success (HTTP 200):**

```json
{
  "policyId": "sha256:compiled-policy-content",
  "ttlSeconds": 300,
  "extensions": {
    "permit-pty": "",
    "permit-agent-forwarding": "",
    "permit-user-rc": ""
  }
}
```

**Fields:**

- `ttlSeconds` (integer, 1–9223372036): Maximum certificate lifetime from **CA signing time**, in whole seconds. For example, `300` means five minutes. Fractional numbers and duration strings are invalid.
- `extensions` (map[string]string): SSH certificate extensions to grant. An empty map grants none.
- `notAfter` (RFC 3339 string, optional): An additional absolute deadline owned by policy, for example `"2026-09-11T17:00:00Z"`. Omit it (or send the zero time) when no additional deadline applies. An expired deadline prevents issuance.
- `policyId` (string): Content ID of the compiled policy, retained in private issuance logs. Built-in Writ supplies its SHA-256 content ID.

CA constructs certificate Key ID from inventory `userName` and exactly one
principal from the requested account and the resolved host's principal mode/domain.
It checks active-user, host, and account restrictions, and signs with:

```text
expiry = min(signing time + ttlSeconds seconds, inventory authentication expiry, optional notAfter)
```

Writ and deployment configuration retain duration syntax such as `5m`.
Writ durations already use whole seconds. The built-in policy rounds fractional
deployment defaults down (`1500ms` becomes `1`) and rejects results below one second. CA checks the integer range
before converting it to its internal duration; it never interprets legacy `ttl`
values as seconds.

A policy deadline cannot extend the authentication lifetime. TTL must be positive;
SSH timestamps are truncated to whole seconds and an interval leaving no usable
lifetime is rejected. CA rechecks the ceiling at signing, so time spent waiting
between policy evaluation and signing cannot extend either absolute deadline.
The built-in policy omits `notAfter`; it no longer echoes authentication expiry.
Writ `until` still controls rule eligibility at evaluation time, not certificate
expiry. No Writ language semantics change here.

### Custom policy migration (API 7)

Upgrade CA, inventory, and policy together, including separately deployed services.
User facts now use plain fields in both inventory responses and policy requests.
Remove `schemas`; replace each group object with its `value` string; move
`department` and `organization` out of the enterprise-extension URI property
and directly into the user object. Group display values are no longer carried.
Identity and group strings retain byte-exact matching. Static YAML is unchanged;
future SCIM adapters translate external records at the inventory boundary.

API 7 replaces the response `ttl` (nanoseconds) with integer `ttlSeconds`.
Divide old durations by 1,000,000,000, rounding down; reject results below one
second or above 9223372036. The signing-time origin and absolute expiry limits
are unchanged. Go policy responses now use `TTLSeconds int64`.

The API 6 input cleanup is retained. It replaces the inventory envelope in `facts` with the projection above:

- Move `facts.directory.user` to `facts.user` and `facts.inventory.host.resource` to `facts.host`.
- Rename the requested host string from `facts.host` to `facts.target`; retain `facts.authentication` unchanged.
- Remove `facts.version`, `facts.resolvedAt`, snapshot wrappers/revisions, and principal metadata. CA validates inventory-to-target binding before projecting facts and signs the projection with the connection.
- Remove `directoryRevision` and `inventoryRevision` from policy responses. CA combines its original revisions with policy's `policyId` for private issuance audit.
- Inventory resolution uses top-level `target` for the requested host, flattens `inventory.host.resource` fields directly into `inventory.host` alongside `principal`, and no longer returns `resolvedAt`; it retains its protocol version and separate directory/host revisions. No upstream freshness guarantee was attached to the removed timestamp.

The output-ownership change introduced in API 5 is retained. The old
`certParams` response is no longer accepted as an authorization grant:

- Convert `certParams.expiration` from nanoseconds to top-level `ttlSeconds` as described above, retaining the signing-time origin.
- Move `certParams.extensions` to top-level `extensions`.
- Move any intentionally tighter `certParams.notAfter` to top-level `notAfter`. Remove it if it only echoed authentication expiry; CA enforces that bound independently.
- Remove response `id`, `certParams.identity`, and `certParams.principals`. CA obtains the ID and username from inventory and derives the sole requested principal itself.
- Retain `policyId` for private audit. Continue authorizing the exact user/host/account request and enforcing policy-owned limits.

Go integrations now use `wire.PolicyResponse` for policy limits and `ca.CertParams`
for local signing inputs. Policy evaluators implement
`Evaluate(context.Context, policy.Connection, *wire.PolicyFacts)`; authentication
comes from those facts rather than duplicate arguments. `pkg/facts` contains the
shared user/authentication/host data types without inventory transport metadata.
`CA.RequestPolicy` returns `ca.Authorization`, which
combines CA-constructed signing inputs with private audit metadata. Client-facing
success responses still contain only the certificate. Combined deployment remains
`epithet server`; static YAML and Writ syntax are unchanged.

**Private non-issuance responses (HTTP 202, 401, 403, or 5xx):**

Error responses are **plain text**, not JSON - the body is the message
itself, with `Content-Type: text/plain` (see `writeError` in
`pkg/policyserver/policyserver.go`):

```
alice@example.com is not authorized for deploy@prod-web-01.example.com: no policy rule allows this access
```

Return 403 for authorization denial or 202 for pending authorization.
CA returns a fixed public message for each outcome and logs the private reason.
A policy 401 rejects the CA service credential and becomes a public 502.
Other non-200 statuses also become public infrastructure errors; none authorize
a certificate. See [public CA errors and pending behavior](ca-errors.md).

### Service authentication (CA → policy server)

Every `POST /` request must carry a short-lived JWT the CA mints per request, signed with the CA's own SSH private key:

```
Authorization: Bearer <jwt>
```

Claims:

| Claim | Meaning |
|---|---|
| `iss` | CA identity: SHA256 fingerprint of the CA's SSH public key |
| `aud` | `"epithet-policy"` |
| `iat` / `exp` | Issued-at / expiry, ~60 seconds apart |
| `jti` | Random token ID |
| `bh` | `base64url(sha256(request body))` — raw, unpadded encoding — binds the token to this exact body (empty string for `GET`) |
| `htm` | HTTP method |
| `htu` | Request target: host + path |

The signing algorithm is derived from the CA's key type: ed25519→EdDSA,
RSA→PS256, ECDSA→ES256/ES384. `htm`/`htu` binding closes a same-body replay
window that body-hashing alone would leave open (e.g. a captured `GET /`
token replayed against a `POST /` with the same empty body).

A minimal Go verifier:

```go
import "github.com/epithet-ssh/epithet/pkg/serviceauth"

verifier, err := serviceauth.NewVerifier(caPubKey) // authorized_keys format
// ...
if err := verifier.Verify(r, body); err != nil {
    http.Error(w, "invalid signature", http.StatusUnauthorized)
    return
}
```

Verification is required — there is no unauthenticated mode.

A complete OpenAPI 3.0 specification is available at [`policy-server-api.yaml`](./policy-server-api.yaml).

## See also

- [OIDC setup guide](./oidc-setup.md) - Provider configuration
- [Architecture](./architecture.md) - How epithet works
- [Example configurations](../examples/policy-server/) - Deployment examples
