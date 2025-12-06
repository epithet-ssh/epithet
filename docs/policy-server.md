# Policy Server Guide

This guide explains how to set up and use epithet's built-in policy server with OIDC-based authorization.

## Overview

The epithet policy server validates OIDC tokens and makes authorization decisions based on a configuration file that maps users to tags, and tags to principals. This enables small teams to deploy epithet quickly without building custom policy infrastructure.

**Key Features:**
- OIDC token validation (works with Google Workspace, Okta, Azure AD, etc.)
- Tag-based authorization for flexible access control
- Per-host policy overrides
- Simple YAML or CUE configuration
- Built-in to the epithet binary (no separate deployment needed)

**Security Note:** SSH certificates issued by epithet can be used on any host that trusts the CA, regardless of host-specific policies in the configuration. Host restrictions are enforced at **certificate issuance time**, not validation time. For tighter security, consider using SSH's `AuthorizedPrincipalsCommand` on target hosts to enforce additional checks.

## Quick Start

### 1. Get the CA Public Key

The policy server needs your CA's public key to verify requests are coming from the legitimate CA:

```bash
# If running the CA server locally
curl http://localhost:8080/

# Or extract from a file
cat ~/.epithet/ca_key.pub
```

### 2. Create a Policy Configuration File

Create `~/.epithet/policy.yaml` (the policy server loads config from `~/.epithet/*.yaml`):

```yaml
policy:
  # Address to listen on
  listen: "0.0.0.0:9999"

  # CA public key for signature verification
  ca_pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."

  # OIDC configuration for token validation
  oidc:
    issuer: "https://accounts.google.com"
    audience: "your-client-id"

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

### 3. Start the Policy Server

```bash
# Config is loaded from ~/.epithet/policy.yaml
epithet policy

# Or override with CLI flags
epithet policy \
  --ca-pubkey "$(curl -s http://localhost:8080/)" \
  --listen 0.0.0.0:9999
```

### 4. Configure the CA to Use the Policy Server

When starting the CA:

```bash
epithet ca \
  --key ~/.epithet/ca_key \
  --policy http://localhost:9999 \
  --address :8080
```

## Configuration Format

### File Formats

The policy server supports both YAML and CUE formats:

**YAML** (`.yaml` or `.yml`):
```yaml
users:
  alice@example.com: [admin]
```

**CUE** (`.cue`):
```cue
users: {
  "alice@example.com": ["admin"]
}
```

The format is auto-detected based on file extension.

### Configuration Structure

#### Top-Level Fields

All fields go under the `policy:` section in `~/.epithet/*.yaml`:

- **`listen`** (optional): Address to listen on (default: `0.0.0.0:9999`)
- **`ca_pubkey`** (required): SSH public key of the CA for signature verification
- **`oidc`** (required): OIDC configuration object with `issuer` and `audience` fields
- **`users`** (required): Map of user identities to tags
- **`defaults`** (optional): Global policy defaults
- **`hosts`** (optional): Per-host policy overrides
- **`default_expiration`** (optional): Default certificate expiration (e.g., `5m`)

#### Users Section

Maps user identities (typically email addresses from OIDC claims) to tags:

```yaml
users:
  alice@example.com: [admin, dev]
  bob@example.com: [dev]
  charlie@example.com: [ops, security]
```

**Identity Matching:**
- Identity is extracted from the OIDC token's `email` claim (preferred)
- Falls back to `sub` claim if `email` is not present
- Must match exactly (case-sensitive)

#### Defaults Section

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

#### Hosts Section

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

## Authorization Logic

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

### Example Authorization Flow

**Configuration:**
```yaml
users:
  alice@example.com: [admin, eng]
  bob@example.com: [eng]

defaults:
  allow:
    wheel: [admin]
    developers: [eng]

hosts:
  prod-db:
    allow:
      dbadmins: [admin]
```

**Certificate Principals Issued:**

1. **Alice** (`alice@example.com`, tags: `[admin, eng]`)
   - Certificate principals: `["dbadmins", "developers", "wheel"]`
   - From global defaults: `wheel` (admin tag), `developers` (eng tag)
   - From prod-db host: `dbadmins` (admin tag)

2. **Bob** (`bob@example.com`, tags: `[eng]`)
   - Certificate principals: `["developers"]`
   - From global defaults: `developers` (eng tag)
   - Does NOT get `wheel` or `dbadmins` (lacks admin tag)

**SSH Access Examples (with AuthorizedPrincipalsFile):**

Assuming target hosts have `/etc/ssh/auth_principals/root` containing `wheel`:

- `ssh root@any-server`: Alice ✓ (cert has wheel), Bob ✗ (cert lacks wheel)

Assuming `/etc/ssh/auth_principals/ubuntu` contains `developers`:

- `ssh ubuntu@any-server`: Alice ✓ (cert has developers), Bob ✓ (cert has developers)

Assuming `/etc/ssh/auth_principals/postgres` contains `dbadmins`:

- `ssh postgres@prod-db`: Alice ✓ (cert has dbadmins), Bob ✗ (cert lacks dbadmins)

## Using AuthorizedPrincipalsFile

Since certificates contain **group principals** (not usernames), you must configure target hosts to map principals to local user accounts.

### Target Host Configuration

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

### How It Works

When a user with a certificate attempts SSH:

1. **sshd validates certificate**: Is it signed by trusted CA? (checks `TrustedUserCAKeys`)
2. **sshd checks principals**: Does certificate contain any principal listed in `/etc/ssh/auth_principals/%u`?
3. **Access granted** if certificate has at least one matching principal

**Example:**

Alice's certificate has principals: `["wheel", "developers", "dbadmins"]`

```bash
# Alice tries to SSH as root
ssh root@server
# → sshd checks /etc/ssh/auth_principals/root (contains: wheel)
# → Alice's cert has "wheel" → ACCESS GRANTED

# Alice tries to SSH as ubuntu
ssh ubuntu@server  
# → sshd checks /etc/ssh/auth_principals/ubuntu (contains: developers, operators)
# → Alice's cert has "developers" → ACCESS GRANTED

# Alice tries to SSH as deploy
ssh deploy@server
# → sshd checks /etc/ssh/auth_principals/deploy (contains: operators)
# → Alice's cert does NOT have "operators" → ACCESS DENIED
```

### Advantages of This Approach

1. **Separation of concerns**: 
   - Epithet policy server controls WHO gets WHICH principals
   - Target hosts control WHICH principals can access WHICH accounts

2. **Fine-grained control**:
   - Different hosts can have different mappings
   - Easy to revoke access to specific accounts without changing certificates

3. **Standard SSH**:
   - Uses built-in OpenSSH features
   - No custom patches or agents required on target hosts

4. **Audit trail**:
   - Certificate shows user identity and all authorized principals
   - Host logs show which principal was used for access

## OIDC Provider Setup

The policy server works with any OIDC-compliant provider. Here are setup guides for common providers:

### Google Workspace

See the [Google Workspace OIDC guide](../examples/google-workspace/README.md) for detailed setup instructions.

**Quick summary:**
1. Create OAuth 2.0 credentials in Google Cloud Console
2. Use `https://accounts.google.com` as the OIDC issuer
3. Configure users by their Google email addresses

### Okta

1. Create a new OIDC application in Okta admin console
2. Use your Okta domain as the issuer: `https://your-domain.okta.com`
3. Configure users by their Okta usernames or emails

### Azure AD

1. Register an application in Azure AD
2. Use `https://login.microsoftonline.com/{tenant-id}/v2.0` as the issuer
3. Configure users by their Azure AD email addresses

### Custom OIDC Provider

Any OIDC-compliant provider will work as long as it:
- Provides a `.well-known/openid-configuration` endpoint
- Issues JWT tokens with standard claims
- Includes `email` or `sub` claim for user identity

## Deployment Patterns

### Single-Server Setup

For development or small teams:

```bash
# Start CA server
epithet ca \
  --key ~/.epithet/ca_key \
  --policy http://localhost:9999 \
  --address :8080 &

# Start policy server (config loaded from ~/.epithet/policy.yaml)
epithet policy &
```

### Production Setup

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

### High Availability

For production deployments, run multiple policy server instances behind a load balancer:

```bash
# Instance 1
epithet policy --config-file policy.yaml --ca-pubkey "..." --port 9999

# Instance 2
epithet policy --config-file policy.yaml --ca-pubkey "..." --port 9998

# Instance 3
epithet policy --config-file policy.yaml --ca-pubkey "..." --port 9997
```

Configure your load balancer to distribute requests across all instances.

## Security Considerations

### Token Validation

- The policy server validates OIDC tokens against the provider's JWKS endpoint
- Token signature, expiration, and issuer are all verified
- Invalid or expired tokens result in 401 Unauthorized

### CA Signature Verification

- Every request from the CA includes a signature created with the CA's private key
- The policy server verifies this signature using the CA's public key
- This prevents token replay attacks and ensures requests come from the legitimate CA

### Certificate Lifetime

- Keep certificate lifetime short (2-10 minutes recommended)
- Short-lived certificates minimize the blast radius if a certificate is compromised
- Users remain authenticated via refresh tokens, so re-authentication is fast

### SSH Certificate Scope

**Important:** SSH certificates are validated by the target host's `sshd` based only on:
- Is the certificate signed by a trusted CA?
- Does the certificate include the requested principal?

The target host does NOT know about host-specific policies in the policy configuration. This means:
- A certificate with principal `root` can be used on ANY host that trusts the CA
- Host restrictions in policy config only apply at certificate issuance time
- If you need tighter control, use `AuthorizedPrincipalsCommand` on target hosts

### Configuration File Security

- Store `policy.yaml` with restricted permissions (600 or 640)
- Avoid committing real user emails or sensitive data to version control
- Consider using environment variables or secrets management for sensitive values

## Troubleshooting

### Common Errors

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
- Check that `ca_pubkey` in the config matches the CA's actual public key
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

## Example Configurations

### Small Team (3-5 developers)

```yaml
policy:
  ca_pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
  oidc:
    issuer: "https://accounts.google.com"
    audience: "your-client-id"

  users:
    alice@team.com: [admin]
    bob@team.com: [dev]
    charlie@team.com: [dev]

  defaults:
    allow:
      root: [admin]
      ubuntu: [dev, admin]
    expiration: "10m"
```

### Development and Production Separation

```yaml
policy:
  ca_pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
  oidc:
    issuer: "https://login.example.com"
    audience: "your-client-id"

  users:
    alice@example.com: [admin, dev]
    bob@example.com: [dev]
    ops@example.com: [ops]

  defaults:
    allow:
      ubuntu: [dev, admin]
    expiration: "10m"

  hosts:
    prod-web-*:            # Note: wildcards not yet supported in v1
      allow:
        deploy: [ops, admin]
      expiration: "2m"

    prod-db-*:
      allow:
        postgres: [admin]
      expiration: "2m"
```

### Multiple Environments with Different Access Levels

```yaml
policy:
  ca_pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
  oidc:
    issuer: "https://sso.company.com"
    audience: "your-client-id"

  users:
    # Engineering
    alice@company.com: [eng-lead, eng]
    bob@company.com: [eng]

    # Operations
    ops-alice@company.com: [ops-lead, ops]
    ops-bob@company.com: [ops]

    # Security
    security@company.com: [security, ops]

  defaults:
    allow:
      ubuntu: [eng, ops]
    expiration: "5m"

  hosts:
    # Development - relaxed policies
    dev-server-01:
      allow:
        root: [eng]
        deploy: [eng]
      expiration: "1h"

    # Staging - moderate policies
    staging-web-01:
      allow:
        deploy: [eng-lead, ops]
      expiration: "10m"

    # Production - strict policies
    prod-web-01:
      allow:
        deploy: [ops-lead]
      expiration: "2m"

    prod-db-01:
      allow:
        postgres: [ops-lead, security]
      expiration: "2m"
```

## Policy Server HTTP API

The CA server communicates with the policy server over HTTP. This section documents the API contract for implementing custom policy servers.

### HTTP Endpoint

**Method:** `POST`
**Content-Type:** `application/json`

### Request Format

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

### Response Format

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

### Signature Verification

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

### OpenAPI Specification

A complete OpenAPI 3.0 specification is available at [`docs/policy-server-api.yaml`](./policy-server-api.yaml).

**Using the specification:**

1. **Generate server code** in your preferred language:
   ```bash
   openapi-generator generate -i docs/policy-server-api.yaml -g python-flask -o policy-server
   openapi-generator generate -i docs/policy-server-api.yaml -g go-server -o policy-server
   ```

2. **Import into AWS API Gateway** or other API gateways that support OpenAPI

3. **Validate requests/responses** using tools like Prism:
   ```bash
   npx @stoplight/prism-cli mock docs/policy-server-api.yaml
   ```

## See Also

- [Policy Configuration Design](./policy-config-design.md) - Detailed design document
- [Google Workspace Setup](../examples/google-workspace/README.md) - OIDC setup for Google
- [Development Tools](./development-tools.md) - Testing with `epithet dev policy`
