# Policy Server Configuration Design

## Overview

This document defines the configuration file format for the built-in OIDC-based policy server (`epithet policy`). The policy server validates OIDC tokens and makes authorization decisions based on static user→policy mappings.

## Design Goals

1. **Simple for small deployments**: Easy to understand and edit by hand
2. **Works with epithet auth oidc**: Primary use case is Google Workspace, Okta, Azure AD
3. **Static mappings**: Adding users requires redeploying the server (acceptable trade-off for simplicity)
4. **Clear authorization model**: Explicit allow/deny with no ambiguity
5. **CUE-based parsing**: Uses CUE for configuration parsing (provides validation, defaults, and future extensibility)

## Configuration File Format

### CUE/YAML Structure

Configuration files can be written in YAML (valid YAML is valid CUE) or native CUE syntax.

```yaml
# CA public key for signature verification
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."

# OIDC provider issuer URL
oidc: "https://accounts.google.com"

# Map user identities (email from OIDC token) to principals
users:
  "a@example.com": [wheel]
  "b@example.com": [dev]

# Default policy settings
defaults:
  allow: [wheel]              # Default principals for allowed users
  expiration: "5m"            # Default certificate expiration
  extensions:
    permit-pty: ""
    permit-agent-forwarding: ""
    permit-user-rc: ""

# Per-host policies (optional, for fine-grained control)
hosts:
  m0001: {}                   # Uses defaults
  v0003:
    allow:
      arch: [dev]             # User "arch" gets [dev] principals on v0003
    expiration: "1h"          # Override expiration for this host
```

### Field Definitions

#### Top-Level Fields

- **`ca_public_key`** (required): CA's SSH public key for signature verification
  - Literal SSH public key string (e.g., `ssh-ed25519 AAAAC3...`)
  - Used to verify the signature in policy requests (prevents token replay)

- **`oidc`** (required): OIDC provider issuer URL
  - Example: `https://accounts.google.com`
  - Used to discover JWKS endpoint (via `{issuer}/.well-known/openid-configuration`)
  - Used to validate the `iss` claim in JWT tokens
  - Must match the issuer configured in `epithet auth oidc`

- **`users`** (required): Map of user identity → principals list
  - Key: User identity from OIDC token (`email` claim, or `sub` if email missing)
  - Value: List of SSH principals to assign in certificates
  - Example: `"alice@example.com": [alice, admin]`

- **`defaults`** (optional): Default policy settings

- **`defaults.allow`** (optional): Default principals for authenticated users
  - If user is authenticated (valid token) but not in `users` map, assign these principals
  - If omitted, unlisted users are denied

- **`defaults.expiration`** (optional): Default certificate expiration
  - Format: Go duration string (e.g., `5m`, `1h`, `2m30s`)
  - Default: `5m` if not specified

- **`defaults.extensions`** (optional): Default SSH certificate extensions
  - Map of extension name → value (typically empty string)
  - Standard extensions: `permit-pty`, `permit-agent-forwarding`, `permit-port-forwarding`, `permit-user-rc`, `permit-X11-forwarding`
  - Default: `{permit-pty: "", permit-agent-forwarding: "", permit-user-rc: ""}` if not specified

- **`hosts`** (optional): Per-host policy overrides
  - Key: Hostname (exact match against `connection.remoteHost`)
  - Value: Host-specific policy settings
  - Allows fine-grained control over access to specific hosts

#### Hosts Section (Per-Host Policies)

Each host entry can override default behavior:

- **`allow`** (optional): Map of user identity → principals for this host
  - Overrides the principals from `users` map for this specific host
  - Example: `allow: { "alice@example.com": [alice] }` - alice gets only [alice] principal on this host (not her default [alice, admin])

- **`expiration`** (optional): Override certificate expiration for this host
  - Format: Go duration string
  - Overrides `defaults.expiration`

- **`extensions`** (optional): Override certificate extensions for this host
  - Map of extension name → value
  - Completely replaces `defaults.extensions` (not merged)

## Authorization Logic

When policy server receives a request for `(user_identity, remoteHost)`:

1. **Validate token signature**: Verify token was signed by trusted OIDC provider
2. **Extract identity**: Get `email` claim (or `sub` if email missing)
3. **Check host-specific policy**: Does `hosts[remoteHost]` exist?
   - **If yes**: Use host-specific policy
     - Check `hosts[remoteHost].allow[user_identity]` for principals
     - If not found, check if user is in global `users` map
     - If not found, check if `defaults.allow` exists
     - If none of the above, deny (403 Forbidden)
   - **If no**: Use global policy
     - Check `users[user_identity]` for principals
     - If not found, check if `defaults.allow` exists
     - If not found, deny (403 Forbidden)
4. **Determine certificate parameters**:
   - Principals: From host-specific `allow`, or global `users`, or `defaults.allow`
   - Expiration: `hosts[remoteHost].expiration` > `defaults.expiration` > `5m`
   - Extensions: `hosts[remoteHost].extensions` > `defaults.extensions` > default set
5. **Return policy response** with principals, expiration, extensions, and hostPattern

### Host Pattern in Response

The policy server returns `hostPattern` in the policy response to enable certificate reuse:
- If using host-specific policy: `hostPattern = remoteHost` (exact match, no reuse)
- If using global policy: `hostPattern = "*"` (can reuse for any host)

This ensures certificates with host-specific overrides are only used for the intended host.

## Example Configurations

### Minimal Configuration (Google Workspace)

```yaml
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc: "https://accounts.google.com"

users:
  "alice@example.com": [alice]
  "bob@example.com": [bob]
```

### Configuration with Defaults

```yaml
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc: "https://accounts.google.com"

users:
  "alice@example.com": [alice, admin]
  "bob@example.com": [bob]

defaults:
  allow: [guest]        # Authenticated but unlisted users get [guest] principal
  expiration: "5m"
  extensions:
    permit-pty: ""
    permit-agent-forwarding: ""
```

### Per-Host Policy Overrides

```yaml
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc: "https://accounts.google.com"

users:
  "alice@example.com": [alice, admin]
  "bob@example.com": [bob]
  "ops@example.com": [ops, root]

defaults:
  expiration: "5m"

hosts:
  prod-db-01:
    # Only ops team can access this host, with shorter expiry
    allow:
      "ops@example.com": [ops]
    expiration: "2m"
  
  jump-host:
    # Everyone can access jump host, but alice gets extra principals
    allow:
      "alice@example.com": [alice, admin, bastion-admin]
    expiration: "10m"
```

### Multi-Tier Access

```yaml
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc: "https://login.microsoftonline.com/{tenant}/v2.0"

users:
  "admin@example.com": [admin, wheel, root]
  "developer@example.com": [dev]
  "contractor@example.com": [contractor]

defaults:
  expiration: "5m"
  extensions:
    permit-pty: ""
    permit-agent-forwarding: ""

hosts:
  prod-web-01:
    allow:
      "admin@example.com": [admin, wheel]
      "developer@example.com": [dev]
    # contractor explicitly not in allow list - denied
  
  staging-web-01:
    # Uses global users map (all users can access with their default principals)
  
  sandbox-01:
    # Anyone authenticated can access sandbox with guest principal
    expiration: "1h"
```

## Implementation Notes

### CUE Parsing

Use `cuelang.org/go/cue` for configuration parsing:

```go
import (
    "cuelang.org/go/cue"
    "cuelang.org/go/cue/cuecontext"
    "cuelang.org/go/cue/load"
)

// Parse config file (YAML or CUE)
ctx := cuecontext.New()
val := ctx.CompileBytes(configFileBytes)

// Decode into Go struct
var config PolicyConfig
err := val.Decode(&config)
```

**Benefits of CUE**:
- Validates structure and types automatically
- Supports both YAML and CUE syntax
- Future: Can add schema validation, constraints, computed fields
- Future: Can use CUE's default value mechanisms

### Token Validation

The policy server must:
1. Fetch JWKS from OIDC provider (cache with TTL)
2. Verify JWT signature using JWKS
3. Validate standard claims:
   - `exp`: Token not expired
   - `iss`: Matches configured issuer
   - `aud`: Matches expected audience (if applicable)
4. Extract identity from `email` or `sub` claim

Use `github.com/coreos/go-oidc/v3/oidc` library (already in dependencies).

### CA Signature Verification

The policy server must:
1. Verify the `signature` field in request using `ca.Verify()`
2. This proves the request came from the legitimate CA
3. Prevents token replay attacks (stolen tokens can't be used directly against policy server)

### Error Responses

- **401 Unauthorized**: Token validation failed (invalid signature, expired, wrong issuer)
- **403 Forbidden**: Token valid but policy denied (user not in allow list)
- **500 Internal Server Error**: Policy server error (config issue, CA signature verification failed)

## Go Struct Definitions

```go
type PolicyConfig struct {
    CAPublicKey string                `json:"ca_public_key"`
    OIDC        string                `json:"oidc"`         // OIDC issuer URL
    Users       map[string][]string   `json:"users"`        // user identity → principals
    Defaults    *DefaultPolicy        `json:"defaults"`
    Hosts       map[string]*HostPolicy `json:"hosts"`       // hostname → host policy
}

type DefaultPolicy struct {
    Allow      []string          `json:"allow,omitempty"`      // Default principals for unlisted users
    Expiration string            `json:"expiration,omitempty"` // Default cert expiration
    Extensions map[string]string `json:"extensions,omitempty"` // Default cert extensions
}

type HostPolicy struct {
    Allow      map[string][]string `json:"allow,omitempty"`      // user → principals for this host
    Expiration string              `json:"expiration,omitempty"` // Override expiration
    Extensions map[string]string   `json:"extensions,omitempty"` // Override extensions
}
```

## Future Enhancements (Out of Scope for v1)

- Group-based policies (check OIDC token groups claim)
- Dynamic policy updates without restart (watch config file)
- Policy conditions (time-based access, require MFA, etc.)
- CUE schema validation and constraints
- CUE-based computed fields (e.g., derive principals from groups)
- Host pattern matching (currently exact match only)

## Security Considerations

1. **Config file contains no secrets**: Only public keys and user→policy mappings
2. **CA signature verification**: Required to prevent token replay attacks
3. **Token expiration**: Always check `exp` claim
4. **JWKS caching**: Cache JWKS but respect TTL (avoid stale keys)
5. **Principle of least privilege**: Use host-specific policies to restrict access
6. **Short certificate expiry**: Use 2-10 minute expiry for privileged access

## Migration Path

For existing `epithet dev policy` users:

**Old (dev policy server)**:
```bash
epithet dev policy \
  --mode allow-all \
  --principals alice,admin \
  --identity alice@example.com \
  --expiration 5m \
  --ca-pubkey https://ca.example.com/public-key
```

**New (policy config file)**:
```yaml
# policy.yaml
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc: "https://accounts.google.com"

users:
  "alice@example.com": [alice, admin]

defaults:
  expiration: "5m"
```

```bash
epithet policy --config policy.yaml --address :9999
```
