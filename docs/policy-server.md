# Policy server guide

This guide explains how to set up and use epithet's built-in policy server with OIDC-based authorization.

## Overview

The epithet policy server validates OIDC tokens and makes authorization decisions based on a configuration file that maps users to tags, and tags to principals. This enables small teams to deploy epithet quickly without building custom policy infrastructure.

**Key Features:**
- OIDC token validation (works with Google Workspace, Okta, Azure AD, etc.)
- Tag-based authorization for flexible access control
- Per-host policy overrides
- Simple YAML or JSON configuration
- Built-in to the epithet binary (no separate deployment needed)

**Security Note:** SSH certificates issued by epithet can be used on any host that trusts the CA, regardless of host-specific policies in the configuration. Host restrictions are enforced at **certificate issuance time**, not validation time. For tighter security, consider using SSH's `AuthorizedPrincipalsCommand` on target hosts to enforce additional checks.

## Quick start

### 1. Get the CA public key

The policy server needs your CA's public key to verify requests are coming from the legitimate CA:

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

  # CA public key for signature verification
  ca-pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."

  # OIDC configuration for token validation
  oidc:
    issuer: "https://accounts.google.com"
    client_id: "your-client-id"

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
        dbadmins: [admin]     # Only admins get 'dbadmins' group on prod-db
      expiration: "2m"        # Shorter expiration for production database

    dev-server:
      allow:
        docker: [eng]         # Engineers get 'docker' group on dev server
      expiration: "10m"       # Longer expiration for dev environment
```

**Important**: Certificates contain **all principals** the user is authorized for (union of global defaults + all host-specific policies). For example, if alice has the `admin` tag, her certificate will include: `wheel`, `dbadmins`, `developers` (if admin also grants eng access), etc.

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

The policy server supports YAML and JSON formats:

**YAML** (`.yaml` or `.yml`):
```yaml
users:
  alice@example.com: [admin]
```

**JSON** (`.json`):
```json
{
  "users": {
    "alice@example.com": ["admin"]
  }
}
```

The format is auto-detected based on file extension or content type.

### Configuration modes

The policy server supports two configuration modes with **different formats**:

#### Inline configuration (in ~/.epithet/*.yaml)

Policy is defined inside your main config file under a `policy:` section:

```yaml
policy:
  ca-pubkey: "ssh-ed25519 ..."
  oidc:
    issuer: "https://accounts.google.com"
  users:
    alice@example.com: [admin]
  defaults:
    allow:
      wheel: [admin]
```

#### Dynamic policy source (--policy-source)

Policy is loaded from a separate file or URL using a **flat format** (no `policy:` wrapper):

```yaml
# No "policy:" wrapper - file is parsed directly
users:
  alice@example.com: [admin]
defaults:
  allow:
    wheel: [admin]
hosts:
  prod-db:
    allow:
      postgres: [admin]
```

Start with: `epithet policy --policy-source ./policy.yaml`

Dynamic sources are reloaded on each request, enabling policy updates without restart.

### Configuration structure

#### Top-level fields

All fields go under the `policy:` section in `~/.epithet/*.yaml`:

- **`listen`** (optional): Address to listen on (default: `0.0.0.0:9999`)
- **`ca-pubkey`** (required): SSH public key of the CA for signature verification
- **`oidc`** (required): OIDC configuration object with `issuer` and `client_id` fields
- **`users`** (required): Map of user identities to tags
- **`defaults`** (optional): Global policy defaults
- **`hosts`** (optional): Per-host policy overrides
- **`defaults.expiration`** (optional): Default certificate expiration under the `defaults:` section (e.g., `5m`)

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

Defines global policies that apply to all hosts unless overridden:

```yaml
defaults:
  allow:
    root: [admin]         # Principal → allowed tags
    ubuntu: [dev, ops]
  expiration: "5m"        # Certificate lifetime
  extensions:             # SSH certificate extensions
    permit-pty: ""
    permit-agent-forwarding: ""
```

**Fields:**
- **`allow`** (optional): Map of principals to allowed tags
  - Key: SSH principal (username on target host)
  - Value: List of tags that grant access to this principal
  - User needs **at least one** matching tag to be authorized
- **`expiration`** (optional): Certificate lifetime (e.g., `5m`, `1h`, `2h30m`)
  - Default: `5m` (5 minutes)
- **`extensions`** (optional): SSH certificate extensions
  - Default: `permit-pty`, `permit-agent-forwarding`, `permit-user-rc`

#### Hosts section

Per-host policy overrides:

```yaml
hosts:
  prod-db-01:
    allow:
      postgres: [dba]      # Override: only dba tag can access postgres
    expiration: "2m"       # Override: shorter expiration
    extensions:            # Override: restricted extensions
      permit-pty: ""
  
  dev-server: {}           # Empty: use defaults for this host
```

**Behavior:**
- If a host is listed, its `allow` rules override global defaults (not merged)
- `expiration` and `extensions` are used if specified, otherwise fall back to defaults
- If a principal is not listed in host-specific `allow`, check global `defaults.allow`
- If a host is not listed at all, use global defaults

> **Important:** SSH certificates are validated by the target host based only on CA trust and principal matching. Host restrictions in policy config only apply at certificate issuance time. Use `AuthorizedPrincipalsCommand` on target hosts for additional enforcement.

## Authorization logic

When a user requests access, the policy server:

1. **Validates the OIDC token**
   - Verifies JWT signature against OIDC provider's JWKS
   - Checks token expiration and issuer
   - Extracts user identity from claims

2. **Looks up user's tags**
   - If user not in `users` map → deny (403)
   - Otherwise, get their tag list

3. **Computes ALL authorized principals**
   - Union of principals from `defaults.allow` where user has matching tags
   - Union of principals from all `hosts[*].allow` where user has matching tags
   - For example, if user has tag `[admin]` and config has:
     - `defaults.allow: {wheel: [admin], developers: [admin]}`
     - `hosts.prod-db.allow: {dbadmins: [admin]}`
   - Then authorized principals = `["dbadmins", "developers", "wheel"]`

4. **Checks requested principal**
   - From the SSH connection's `RemoteUser` field
   - If requested principal is in the authorized set → approve
   - Otherwise → deny (403)

5. **Issues certificate with ALL authorized principals**
   - Principals: ALL principals user is authorized for (not just the one requested)
   - Identity: user's email/identity from token
   - This allows the certificate to be used for any authorized principal
   - Expiration: from host policy or defaults
   - Extensions: from host policy or defaults

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
2. **sshd checks principals**: Does certificate contain any principal listed in `/etc/ssh/auth_principals/%u`?
3. **Access granted** if certificate has at least one matching principal

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
- Token signature verification failed
- Token is expired
- Token issuer doesn't match the OIDC configuration
- Check system clock synchronization

**"Not authorized for principal" (403)**
- User doesn't have the required tags for the requested principal
- Check the user's tags in the configuration
- Verify the principal's allowed tags in `defaults.allow` or `hosts[].allow`

**"Invalid CA signature" (400)**
- The signature from the CA doesn't verify with the configured public key
- Check that `ca-pubkey` in the config matches the CA's actual public key
- Ensure the CA and policy server are using compatible key formats

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

**Method:** `POST`
**Content-Type:** `application/json`

### Request format

The CA sends a JSON request with the following fields:

```json
{
  "token": "authentication-token-from-user",
  "signature": "base64-encoded-signature",
  "connection": {
    "localHost": "user-laptop.local",
    "localUser": "alice",
    "remoteHost": "server.example.com",
    "remoteUser": "ubuntu",
    "port": 22,
    "proxyJump": "",
    "hash": "a1b2c3d4e5f6"
  }
}
```

**Fields:**
- `token` (string): The authentication token from the user (format determined by your auth plugin)
- `signature` (string): Base64-encoded cryptographic signature of the token, signed by the CA's private key
- `connection` (object): Full SSH connection parameters
  - `localHost` (string): User's local hostname (OpenSSH `%l`)
  - `localUser` (string): User's local username
  - `remoteHost` (string): Target SSH server hostname (OpenSSH `%h`)
  - `remoteUser` (string): Target username on remote server (OpenSSH `%r`)
  - `port` (uint): Target SSH port (OpenSSH `%p`)
  - `proxyJump` (string): ProxyJump configuration (OpenSSH `%j`), empty if not used
  - `hash` (string): OpenSSH `%C` hash - unique identifier for this connection

### Response format

**Success (HTTP 200):**

```json
{
  "certParams": {
    "identity": "alice@example.com",
    "principals": ["ubuntu", "root", "deploy"],
    "expiration": "5m0s",
    "extensions": {
      "permit-pty": "",
      "permit-agent-forwarding": "",
      "permit-port-forwarding": "",
      "permit-user-rc": "",
      "permit-X11-forwarding": ""
    }
  },
  "policy": {
    "hostPattern": "*.example.com"
  }
}
```

**Fields:**
- `certParams.identity` (string): Certificate identity/key ID (for audit logs)
- `certParams.principals` ([]string): List of usernames this cert can authenticate as
- `certParams.expiration` (string): Certificate validity duration (e.g., "5m", "10m", "1h")
- `certParams.extensions` (map[string]string): SSH certificate extensions to grant
- `policy.hostPattern` (string): Glob pattern for hosts this certificate is valid for

**Denial (HTTP 403 or 401):**

Return any non-200 status code to deny the certificate request.

### Signature verification

**IMPORTANT:** Your policy server must verify the signature before processing the request. This proves the request came from your CA server and not a malicious actor.

```go
import "github.com/epithet-ssh/epithet/pkg/ca"

// Verify signature (CA_PUBKEY is your CA's public key in authorized_keys format)
err := ca.Verify(CA_PUBKEY, token, signature)
if err != nil {
    // Invalid signature - reject the request
    http.Error(w, "invalid signature", http.StatusUnauthorized)
    return
}
```

A complete OpenAPI 3.0 specification is available at [`policy-server-api.yaml`](./policy-server-api.yaml).

## See also

- [OIDC setup guide](./oidc-setup.md) - Provider configuration
- [Architecture](./architecture.md) - How epithet works
- [Example configurations](../examples/policy-server/) - Deployment examples
