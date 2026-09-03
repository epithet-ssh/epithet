# Policy server guide

This guide explains how to set up and use epithet's built-in policy server with OIDC-based authorization.

## Overview

The epithet policy server validates OIDC tokens and makes authorization decisions by evaluating a **writ policy file** against an **inventory** of users and hosts. Policy rules say who may reach which account on which hosts; the inventory says who the users are (SCIM-shaped records) and what the hosts are (names plus labels).

**Key features:**
- OIDC token validation (works with Google Workspace, Okta, Azure AD, etc.)
- A readable, order-independent policy language (`.writ`) with explicit `allow`/`deny` rules — deny always wins
- SCIM-modeled user inventory (groups, type, department, organization) and labeled host inventory, pluggable behind an interface (static files today)
- Certificates minted per connection, using either compatible account-name principals or destination-bound hashed principals
- Certificate validity clamped to the auth token's remaining lifetime
- `epithet policy --check` validates policy + inventory without starting a server
- Built-in to the epithet binary (no separate deployment needed)

**Security boundary:** `account-name`, the compatibility default,
puts the requested account name (for example, `root`) in the SSH certificate.
It does not put the host identity in the credential. A certificate authorized
for `root@dev-1` can therefore authenticate as `root` on `prod-1` while it
remains valid if both hosts trust the same CA. Treat host selectors in this
mode as issuance-time conditions and the effective credential scope as
`account@CA-trust-domain`, not `account@host`.

`epithet-principal-v1` makes issuance destination-bound using the v1 encoding.
The policy server derives a versioned principal from the inventory host ID and
requested account name after authorizing the human-readable `account@host`
tuple. An offline `AuthorizedPrincipalsCommand` on the target derives the same
value from its local host ID and account name. It requires no per-account
registry, account synchronization, or online authorization check by sshd.
Static inventory supports this today for exact hosts. Authenticated managed
registration and clone detection remain control-plane work rather than
policy-language features; routine SSH host-key rotation is independent.

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
deny  type:contractor -> *@$prod, label "no-contractors-in-prod"
```

### 3. Write an inventory file

Create `~/.epithet/inventory.yaml`:

```yaml
users:
  - userName: alice@example.com     # matched against the OIDC identity
    groups: [SRE]
    userType: employee
  - userName: bob@example.com
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
epithet policy --check \
  --policy-file ~/.epithet/policy.writ \
  --inventory ~/.epithet/inventory.yaml

# Start (flags may instead come from the policy: config section)
epithet policy \
  --policy-file ~/.epithet/policy.writ \
  --inventory ~/.epithet/inventory.yaml \
  --ca-pubkey "$(curl -s http://localhost:8080/)" \
  --oidc-issuer https://accounts.google.com \
  --oidc-client-id your-client-id \
  --listen 0.0.0.0:9999
```

**Important:** Each issued certificate carries exactly one principal for the
requested connection, never the union of every account the user could reach.
A certificate is minted fresh for every connection past the broker's local
cache of still-valid agents. Destination binding only applies when the
resolved host's effective mode is `epithet-principal-v1` and the target is
configured to validate the derived principal.

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
| users | `id:"alice@example.com"`, `group:SRE`, `type:employee`, `dept:Platform`, `org:Acme`, `*` |
| accounts | a name (`root`), a glob (`deploy-*`), `*` |
| hosts | a name (`prod-db-1`), a glob (`*.example.com`), a label selector (`{env=prod, role=db}`), `*` |

- `[]` makes a union: `allow [$sre, $dba] -> [ubuntu, deploy]@$prod`.
- `{}` entries AND: `{env=prod, role=db}` requires both labels.
- Globs (`*` and `?` only) match **names, never attribute values** — `group:SRE*` is an error; quote a value containing glob characters (`group:"weird*name"`) to match it literally. `*` crosses dots: `*.example.com` matches `a.b.example.com`.
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

The inventory answers two questions at evaluation time: who is this identity, and what is this host? It is pluggable by design (databases are the expected future); the built-in implementation is one or more static YAML files given via `--inventory` (repeatable, globs allowed). Files concatenate; duplicate users or hosts across files are a load error, and unknown fields are an error rather than a silently ignored typo.

### Users

User records follow the SCIM (RFC 7643) shape and field names:

```yaml
users:
  - userName: alice@example.com   # the identity key
    active: true                  # default true; false matches nothing, ever
    groups: [SRE, Engineering]    # matched by group:
    userType: employee            # matched by type:
    department: Platform          # matched by dept:
    organization: Acme            # matched by org:
```

The OIDC token's identity (the `email` claim, falling back to `sub`) is compared **byte-for-byte** against `userName`. An identity with no inventory record, or with `active: false`, is denied structurally — no policy rule can grant it anything.

### Hosts

```yaml
hosts:
  - name: prod-db-1               # exact entry (name is lowercased at load)
    labels: {env: prod, role: db}
    accounts: [root, postgres]    # optional account grounding — see below
    principal-mode: epithet-principal-v1
    host-id: "epithet-host-v1-..." # generated by epithet host enroll
  - pattern: "ci-runner-*"        # pattern entry: writ glob
    labels: {env: ci}
    principal-mode: account-name
```

A connection's host must resolve in the inventory or the request is denied — this is what makes label selectors trustworthy. Two entry forms:

- **Exact entries** (`name:`) are individual hosts, looked up first.
- **Pattern entries** (`pattern:`) synthesize a host for any requested name they match, adopting the requested name and carrying the entry's labels. This is the escape hatch for short-lived fleets (VM pools, CI runners) that follow a naming pattern but cannot be enumerated. Patterns match in file order; first match wins.

`principal-mode` overrides the deployment default for that exact host or
pattern. An exact host whose effective mode is `epithet-principal-v1` must have
one canonical `host-id`, copied exactly from the target's host-ID file or
enrollment output. Static patterns cannot use `epithet-principal-v1` or provide
a shared `host-id`, because one ID for a fleet would erase destination
isolation. Under a hashed deployment default, give ephemeral patterns an explicit
`principal-mode: account-name` fallback. Exact entries win before
patterns; otherwise the first matching pattern wins.

Multiple exact names may intentionally use the same host ID as aliases;
they derive the same principal and therefore form one destination boundary.
Static inventory cannot distinguish a deliberate alias from a cloned host, so
do not copy an ID across independent machines. Clone detection and
authoritative identity lifecycle are responsibilities of future managed
inventory.

**Account grounding:** if a host entry lists `accounts`, certificates are only issuable for accounts in that list — even a policy `*` cannot reach an unlisted account. If the entry has no `accounts` key, account matching is ungrounded and rules match against the requested account name directly.

## Configuration

All policy-server settings can live under the `policy:` section of `/etc/epithet/*.yaml` or `~/.epithet/*.yaml` (or a file given with `--config`). Keys use the CLI flag names verbatim (kebab-case):

```yaml
policy:
  listen: "0.0.0.0:9999"
  ca-pubkey: "ssh-ed25519 AAAA..."
  oidc:
    issuer: "https://accounts.google.com"
    client-id: "your-client-id"
  policy-file: /etc/epithet/policy.writ
  inventory:
    - /etc/epithet/inventory.yaml
  principal-mode: epithet-principal-v1
  default-expiration: 5m
```

- **`listen`** (optional): address to listen on (default `0.0.0.0:9999`). A `unix:///path/to/policy.sock` value listens on a Unix domain socket; this is how `epithet server` wires its subprocesses together.
- **`ca-pubkey`** (required): the CA's SSH public key (URL, file path, or literal), used to verify the CA's service JWT.
- **`oidc`** (required): `issuer` and `client-id` — `client-id` is required so audience checking can never be silently skipped.
- **`policy-file`** (required): the writ policy file.
- **`inventory`** (required): inventory file paths or globs.
- **`principal-mode`** (optional): deployment default, either `account-name` (the compatibility default) or `epithet-principal-v1`. A host entry's `principal-mode` overrides it. Naming the concrete protocol version allows different hosts to remain on v1 or move to a future version independently during rollout.
- **`default-expiration`** (optional): cert TTL when no satisfied rule sets a `ttl` (default `5m`). Always further clamped to the auth token's remaining lifetime.
- **`extension`** (flag only): repeatable `name=value` cert extensions.

Policy and inventory are read once at startup; picking up changes is a process restart. `epithet policy --check` validates the pair (parse and compile errors with positions, unknown require/when/notify references, warnings such as unused macros or already-expired `until` rules) and exits non-zero on errors.

## Authorization logic

For each request `(identity, account@host)` the evaluator (`pkg/policyserver/writpolicy` over `pkg/writ/eval`):

1. **Validates the OIDC token** — signature against the provider's JWKS, expiry, issuer, audience — and extracts the identity and token expiry.
2. **Structural gates** — the identity must resolve to an `active` inventory user; the host must resolve in the inventory; if the host lists accounts, the requested account must be among them. Any failure → 403, regardless of policy text.
3. **Collects matching rules** — a rule matches when its user, account, and host expressions all match.
4. **Deny wins** — any matching deny → 403, always; no allow can override. The denial names the rule's label (or content id).
5. **Issues** if any allow survives: `principals` contains exactly one value — either the requested account name or its destination-bound derivation, according to the resolved host's mode. `expiration` is the minimum `ttl` among satisfied allows (else the default), `notAfter` is the token's expiry, and `extensions` are the deployment set.

Evaluator or inventory failures fail **closed** (500), never "treat as no match".

## Target host configuration

### Host enrollment

Install the same Epithet binary on the target, then bootstrap its identity and
CA trust anchor from the CA URL:

```console
$ sudo epithet host enroll --ca-url https://epithet.example.com/
epithet-host-v1-...
```

The command validates the CA response before changing local state and will not
replace a different existing CA key. It is safe to rerun. On Linux the default
files are `/var/lib/epithet/host-id` and
`/var/lib/epithet/epithet-ca.pub`; the native state directory is
`/var/db/epithet` on the BSDs, `/var/opt/epithet` on Solaris, illumos, and AIX,
`/Library/Application Support/Epithet` on macOS, and `%ProgramData%\Epithet`
on Windows. Use `--host-id-file` and `--ca-pubkey-file` during enrollment to
select another layout or to support an otherwise unknown platform.

The printed host ID is the value to put in this host's static-inventory entry.

### Destination-bound hashed principals

Point sshd at the enrolled files. The authorized-principals command is entirely
local: it hashes the canonical host ID and the account supplied as `%u`, then
prints the one principal sshd should accept.

```ssh_config
TrustedUserCAKeys /var/lib/epithet/epithet-ca.pub
AuthorizedPrincipalsCommand /usr/local/bin/epithet host authorized-principals --host-id-file /var/lib/epithet/host-id %u
AuthorizedPrincipalsCommandUser nobody
```

The binary, host-ID file, and their parent directories must meet OpenSSH's
ownership and permissions checks and be readable by the configured command
user. The ID is not secret, but only root should be able to change it. Validate
the sshd configuration before reloading it. Put the exact `epithet-host-v1-...`
text from the file in the matching inventory entry's `host-id`.

The host ID is independent of SSH transport keys, so routine host-key rotation
does not change principals. Changing the host ID means enrolling a new host;
it is not an in-place rotation. The temporary `--accept-account-name` option
also emits `%u` for a bounded migration from account-name certificates; while enabled, it restores the
broader `account@CA-trust-domain` acceptance boundary and should not become
permanent.

The v1 derivation is public in `pkg/principal`: SHA-256 over three RFC 4251 SSH
strings — `epithet-principal-v1`, the canonical host-ID text, and the byte-exact
account name — rendered as `epithet-principal-v1-` plus unpadded
base64url. See the [principal protocol](./principals.md) for the normative byte
encoding and test vector. A bespoke policy server can use this protocol and
the same on-host helper.

Deleting and recreating an account with the same name on the same host
preserves its derived principal. Any exposure from a previously issued
certificate remains bounded by that certificate's lifetime.

### Account-name compatibility

The compatibility mode names the SSH username the client requested
as the certificate's sole principal. sshd's default principal matching is
therefore enough, and no `AuthorizedPrincipalsFile` mapping is required.

**Configure sshd** (`/etc/ssh/sshd_config`):

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
host identity.

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
epithet policy --check --policy-file /etc/epithet/policy.writ --inventory /etc/epithet/inventory.yaml
```

## Troubleshooting

### Common errors

**"user does not resolve to an active inventory user" (403)**
- The OIDC token's email/sub claim doesn't match any inventory `userName` (byte-for-byte, case-sensitive), or the record has `active: false`
- Verify the OIDC provider is sending the expected claim

**"host is not in inventory" (403)**
- The connection's host name matches no exact inventory entry and no pattern entry
- Remember host names are lowercased; patterns use writ globs (`*`, `?`)

**"denied by rule ..." (403)**
- A `deny` rule matched; the message names its label or content id

**"no policy rule allows this access" (403)**
- No `allow` rule matched the (user, account, host) tuple

**"policy references unknown requirement/flag/notify target" (at startup)**
- The policy uses `require`, `when`, or `notify` but no plugin with that name is registered — the static server currently registers none

**"Invalid token" (401)**
- User JWT signature verification failed, token expired, or issuer/audience mismatch
- Check system clock synchronization

**"request verification failed" (401)**
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

A single route, `/`, handles both methods:

- **`GET /`** — anonymous discovery: returns the OIDC bootstrap config the CA passes through on its own `/discovery` endpoint
- **`POST /`** — cert evaluation request

Both require a valid CA-minted service JWT (see [Service authentication](#service-authentication-ca--policy-server)) — there is no unauthenticated variant of either.

### Discovery request

```
GET /
Authorization: Bearer <service JWT>
```

Response (`HTTP 200`):

```json
{
  "auth": {
    "issuer": "https://accounts.google.com",
    "client_id": "your-client-id"
  }
}
```

`client_secret` is included (unencrypted) only if configured. There are no
host-match patterns in this response — host gating lives entirely in the
user's own ssh config.

### Cert evaluation request format

```
POST /
Authorization: Bearer <service JWT>
Content-Type: application/json
```

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "connection": {
    "remoteHost": "server.example.com",
    "remoteUser": "ubuntu",
    "port": 22,
    "proxyJump": "",
    "hash": "a1b2c3d4e5f6"
  }
}
```

**Fields:**
- `token` (string): The user's ID token — always a JWT
- `connection` (object): SSH connection parameters
  - `remoteHost` (string): Target SSH server hostname (OpenSSH `%h`)
  - `remoteUser` (string): Target account name on the remote server (OpenSSH `%r`); the policy server encodes this account according to the resolved host's principal mode
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
  "certParams": {
    "identity": "alice@example.com",
    "principals": ["ubuntu"],
    "expiration": 300000000000,
    "notAfter": "2026-08-13T18:30:00Z",
    "extensions": {
      "permit-pty": "",
      "permit-agent-forwarding": "",
      "permit-user-rc": ""
    }
  }
}
```

**Fields:**
- `certParams.identity` (string): Certificate identity/key ID (for audit logs)
- `certParams.principals` ([]string): Exactly one entry — either the requested account name or a destination-bound derived principal, according to the resolved host's mode
- `certParams.expiration` (integer): Certificate validity, in **nanoseconds** (this is `time.Duration` marshaled by Go's default `encoding/json`, i.e. an integer, not a duration string like `"5m"`)
- `certParams.notAfter` (string, RFC 3339, optional): Absolute ceiling on certificate validity, derived from the user token's expiry. The CA signs with `min(now + expiration, notAfter)`. Omitted (zero value) means no ceiling beyond `expiration`.
- `certParams.extensions` (map[string]string): SSH certificate extensions to grant

**Denial (HTTP 401, 403, or 500):**

Error responses are **plain text**, not JSON - the body is the message
itself, with `Content-Type: text/plain` (see `writeError` in
`pkg/policyserver/policyserver.go`):

```
alice@example.com is not authorized for deploy@prod-web-01.example.com: no policy rule allows this access
```

Return any non-200 status code with a plain-text body to deny the
certificate request.

### Service authentication (CA → policy server)

Every request — `GET /` and `POST /` alike — must carry a short-lived JWT the CA mints per request, signed with the CA's own SSH private key:

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
