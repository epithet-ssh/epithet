# Policy server guide

This guide explains how to set up and use epithet's built-in policy server with OIDC-based authorization.

## Overview

The epithet policy server validates OIDC tokens and makes authorization decisions based on a configuration file that maps users to tags, and tags to principals. This enables small teams to deploy epithet quickly without building custom policy infrastructure.

**Key Features:**
- OIDC token validation (works with Google Workspace, Okta, Azure AD, etc.)
- Tag-based authorization for flexible access control
- Per-host policy overrides, matched longest-pattern-first
- Certificates minted per connection, carrying only the requested principal
- Certificate validity clamped to the auth token's remaining lifetime
- YAML config files (`.json` also works, since JSON is valid YAML - see
  "Configuration format" below)
- Built-in to the epithet binary (no separate deployment needed)

**Security Note:** SSH certificates issued by epithet can be used on any host that trusts the CA, regardless of host-specific policies in the configuration. Host restrictions are enforced at **certificate issuance time**, not validation time. For tighter security, consider using SSH's `AuthorizedPrincipalsCommand` on target hosts to enforce additional checks.

## Quick start

### 1. Get the CA public key

The policy server needs your CA's public key to verify the CA-minted service JWT on every request (see [Service authentication](#service-authentication-ca--policy-server) below):

```bash
# If running the CA server locally
curl http://localhost:8080/

# Or extract from a file
cat ~/.epithet/ca_key.pub
```

### 2. Create a policy configuration file

Create `~/.epithet/policy.yaml` (the policy server loads config from `~/.epithet/*.yaml`):

```yaml
# Inline format: requires "policy:" wrapper
policy:
  # Address to listen on
  listen: "0.0.0.0:9999"

  # CA public key, used to verify the CA's service JWT on every request
  ca-pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."

  # OIDC configuration for token validation
  oidc:
    issuer: "https://accounts.google.com"
    client-id: "your-client-id"

  # Map users (by email/identity) to tags
  users:
    alice@example.com: [admin, dev]
    bob@example.com: [dev]
    charlie@example.com: [ops]

  # Global defaults for all hosts
  defaults:
    # Map principals to allowed tags
    allow:
      root: [admin]           # Users with 'admin' tag can log in as root
      ubuntu: [dev, ops]      # Users with 'dev' or 'ops' tag can log in as ubuntu
      deploy: [ops]           # Users with 'ops' tag can log in as deploy

    # Default certificate expiration
    expiration: "5m"

    # Default SSH certificate extensions
    extensions:
      permit-pty: ""
      permit-agent-forwarding: ""
      permit-user-rc: ""

  # Per-host policy overrides (optional)
  hosts:
    prod-db-01:
      allow:
        dbadmins: [admin]     # Only admins get 'dbadmins' access on prod-db
      expiration: "2m"        # Shorter expiration for production database

    dev-server:
      allow:
        docker: [eng]         # Engineers get 'docker' access on dev server
      expiration: "10m"       # Longer expiration for dev environment
```

**Important:** Each issued certificate carries **only the principal actually requested** for that connection (`ssh <principal>@<host>`), never the union of everything the user's tags could reach elsewhere. A certificate is minted fresh for every connection past the broker's local cache of still-valid agents — there is no cross-connection certificate cache and nothing the policy server decides ever leaves the policy server on the wire.

### 3. Start the policy server

```bash
# Config is loaded from ~/.epithet/policy.yaml
epithet policy

# Or override with CLI flags
epithet policy \
  --ca-pubkey "$(curl -s http://localhost:8080/)" \
  --listen 0.0.0.0:9999
```

### 4. Configure the CA to use the policy server

When starting the CA:

```bash
epithet ca \
  --key ~/.epithet/ca_key \
  --policy http://localhost:9999 \
  --listen :8080
```

## Configuration format

### File formats

Config files are parsed as YAML. The default search paths match `*.yaml`,
`*.yml`, and `*.json` under `/etc/epithet/` and `~/.epithet/` (see
`defaultConfigPatterns` in `cmd/epithet/main.go`), so a `.json` file is
picked up too - not because its format is detected, but because JSON is a
syntactic subset of YAML and the same YAML parser (`gopkg.in/yaml.v3`)
accepts it directly.

There is no per-file content-type or extension sniffing - every matched file
goes through the same YAML unmarshal call.

### Configuration mode

Policy is defined inside your main config file under a `policy:` section:

```yaml
policy:
  ca-pubkey: "ssh-ed25519 ..."
  oidc:
    issuer: "https://accounts.google.com"
    client-id: "your-client-id"
  users:
    alice@example.com: [admin]
  defaults:
    allow:
      wheel: [admin]
```

Policy is read once at startup; picking up changes requires restarting the
server (dynamic reload from a URL was removed - config is the only source).

### Configuration structure

#### Top-level fields

All fields go under the `policy:` section in `~/.epithet/*.yaml`:

- **`listen`** (optional): Address to listen on (default: `0.0.0.0:9999`)
- **`ca-pubkey`** (required): SSH public key of the CA, used to verify the CA's service JWT
- **`oidc`** (required): OIDC configuration object with `issuer` and `client-id` fields (config-file keys are kebab-case, derived from the CLI flag names — see the note below) — `client-id` is required so audience checking can never be silently skipped
- **`users`** (required): Map of user identities to tags
- **`defaults`** (optional): Global policy defaults
- **`hosts`** (optional): Per-host policy overrides

> **Key casing note:** `listen`, `ca-pubkey`, `oidc.issuer`, `oidc.client-id`,
> `oidc.client-secret`, and `default-expiration` are resolved by Kong from
> the CLI flag names, so their config-file keys are **kebab-case** (e.g.
> `client-id`, not `client_id`) — using the underscored spelling silently
> fails to populate the value and surfaces later as "oidc.client_id is
> required". `users`, `defaults`, and `hosts` (and the fields inside
> `Rules`: `allow`, `expiration`, `extensions`) are decoded separately by a
> plain YAML unmarshal against Go struct tags, which happen to have no
> multi-word keys today so the casing question doesn't currently bite there.
> This split-brain config loading (two different resolvers reading the same
> file) is tracked for cleanup in the policy-server config parsing rework
> task (see `ideas/oidc-only-auth.md` §7).

#### Users section

Maps user identities (typically email addresses from OIDC claims) to tags:

```yaml
users:
  alice@example.com: [admin, dev]
  bob@example.com: [dev]
  charlie@example.com: [ops, security]
```

**Identity matching:**
- Identity is extracted from the OIDC token's `email` claim (preferred)
- Falls back to `sub` claim if `email` is not present
- Must match exactly (case-sensitive)

#### Defaults section

Defines global rules that apply to all hosts unless overridden:

```yaml
defaults:
  allow:
    root: [admin]         # Principal → allowed tags
    ubuntu: [dev, ops]
  expiration: "5m"        # Certificate lifetime
  extensions:              # SSH certificate extensions
    permit-pty: ""
    permit-agent-forwarding: ""
```

**Fields:**
- **`allow`** (optional): Map of principals to allowed tags
  - Key: SSH principal (username on target host)
  - Value: List of tags that grant access to this principal
  - User needs **at least one** matching tag to be authorized for the requested principal
- **`expiration`** (optional): Certificate lifetime (e.g., `5m`, `1h`, `2h30m`)
  - Default: `5m` (5 minutes)
  - Always further clamped to the auth token's remaining lifetime (`NotAfter`) — a certificate never outlives the session that requested it
- **`extensions`** (optional): SSH certificate extensions
  - Default: `permit-pty`, `permit-agent-forwarding`, `permit-user-rc`

#### Hosts section

Per-host policy overrides, keyed by a host pattern:

```yaml
hosts:
  prod-db-01:
    allow:
      postgres: [dba]      # Override: only dba tag can access postgres
    expiration: "2m"       # Override: shorter expiration
    extensions:            # Override: restricted extensions
      permit-pty: ""

  "*.dev.example.com": {}  # Empty: use defaults for these hosts
```

**Host pattern matching:** patterns are matched against `remoteHost` using
Go's `path.Match` semantics (the same glob syntax as `doublestar`/shell
globs, since `path.Match`'s `*` only refuses to cross `/`, which never
appears in a hostname). This means **`*` crosses dot boundaries**:
`*.example.com` matches `a.b.example.com`, not just single-label hosts like
`a.example.com`. Only `/` is a boundary character for `*`.

Since YAML maps don't preserve key order, patterns are evaluated
**longest-pattern-first** (ties broken lexicographically) — a deterministic,
config-order-independent way to prefer the most specific match. The first
pattern that matches the connection's host contributes its `expiration` and
`extensions` overrides (falling back to `defaults` for anything it doesn't
set); `allow` rules from the matching host pattern and from `defaults` are
merged when deciding whether the requested principal is authorized.

> **Important:** SSH certificates are validated by the target host based only on CA trust and principal matching. Host restrictions in policy config only apply at certificate issuance time. Use `AuthorizedPrincipalsCommand` on target hosts for additional enforcement.

## Authorization logic

When a user requests access, the policy server (`pkg/policyserver/evaluator`):

1. **Validates the OIDC token**
   - Verifies JWT signature against OIDC provider's JWKS
   - Checks token expiration, issuer, and audience (`client_id`)
   - Extracts user identity and the token's expiry from claims

2. **Looks up the user's tags**
   - If user not in `users` map → deny (403)
   - Otherwise, get their tag list

3. **Checks the one requested principal**
   - The merged `allow` rules (matching host pattern + defaults) for the requested principal must include at least one of the user's tags
   - If not authorized → deny (403)

4. **Issues a certificate naming only that principal**
   - `principals`: exactly `[requestedPrincipal]` — never a union of everything the user could reach
   - `identity`: user's email/identity from the token, for audit logs
   - `expiration`: from the matching host pattern or defaults
   - `notAfter`: the token's expiry — an absolute ceiling the CA clamps against
   - `extensions`: from the matching host pattern or defaults

## Using AuthorizedPrincipalsFile

Since certificates contain **group principals** (not usernames), you must configure target hosts to map principals to local user accounts.

### Target host configuration

**1. Configure sshd** (`/etc/ssh/sshd_config`):

```ssh_config
# Trust the epithet CA
TrustedUserCAKeys /etc/ssh/ca/epithet.pub

# Use AuthorizedPrincipalsFile to map principals to users
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

**2. Create principal mapping files:**

For each local user, create `/etc/ssh/auth_principals/[username]` listing which principals can access that account:

```bash
# /etc/ssh/auth_principals/root
wheel

# /etc/ssh/auth_principals/ubuntu
developers
operators

# /etc/ssh/auth_principals/postgres
dbadmins
postgres

# /etc/ssh/auth_principals/deploy
operators
```

**3. Set permissions:**

```bash
sudo chmod 644 /etc/ssh/auth_principals/*
```

### How it works

When a user with a certificate attempts SSH:

1. **sshd validates certificate**: Is it signed by trusted CA? (checks `TrustedUserCAKeys`)
2. **sshd checks principals**: Does the certificate's single principal appear in `/etc/ssh/auth_principals/%u`?
3. **Access granted** if the certificate's principal matches

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
# Config is loaded from ~/.epithet/policy.yaml (or specify --config for another location)
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

## Troubleshooting

### Common errors

**"User not in users list" (403)**
- The OIDC token's email/sub claim doesn't match any entry in the `users` map
- Check that the email in the token matches exactly (case-sensitive)
- Verify the OIDC provider is sending the expected claim

**"Invalid token" (401)**
- User JWT signature verification failed
- Token is expired
- Token issuer or audience doesn't match the OIDC configuration
- Check system clock synchronization

**"Not authorized for" (403)**
- User doesn't have a tag matching the requested principal's `allow` rules
- Check the user's tags in the configuration
- Verify the principal's allowed tags in `defaults.allow` or the matching `hosts[].allow`

**"request verification failed" (401)**
- The CA's service JWT failed verification: expired (>60s old), wrong `aud`, body-hash mismatch, method/target mismatch, or the wrong signing key
- Check that `ca-pubkey` in the config matches the CA's actual public key

### Debugging

Enable verbose logging:

```bash
epithet -vv policy
```

Check policy server logs for:
- Token validation results
- User tag lookups
- Authorization decisions
- Configuration loading errors

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
  - `remoteUser` (string): Target username on remote server (OpenSSH `%r`) — the single principal the caller is asking for
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
- `certParams.principals` ([]string): Exactly one entry — the requested principal
- `certParams.expiration` (integer): Certificate validity, in **nanoseconds** (this is `time.Duration` marshaled by Go's default `encoding/json`, i.e. an integer, not a duration string like `"5m"`)
- `certParams.notAfter` (string, RFC 3339, optional): Absolute ceiling on certificate validity, derived from the user token's expiry. The CA signs with `min(now + expiration, notAfter)`. Omitted (zero value) means no ceiling beyond `expiration`.
- `certParams.extensions` (map[string]string): SSH certificate extensions to grant

**Denial (HTTP 403 or 401):**

```json
{"error": "User alice not authorized for deploy@prod-web-01.example.com"}
```

Return any non-200 status code with this shape to deny the certificate request.

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
