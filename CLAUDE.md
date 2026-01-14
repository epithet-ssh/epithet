# CLAUDE.md

**Note**: This project uses yatl (Yet Another Task List) for task tracking. Use `yatl` commands instead of markdown TODOs. Tasks are stored in `.tasks/` directory.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Correctness over convenience

* Model the full error space—no shortcuts or simplified error handling. 
* Handle all edge cases, including race conditions, signal timing, and platform differences.
* Use the type system to encode correctness constraints.
* Prefer compile-time guarantees over runtime checks where possible.

## User experience as a primary driver

* Provide structured, helpful error messages for diagnostics
* Make progress reporting responsive and informative.
* Maintain consistency across platforms even when underlying OS capabilities differ. Use OS-native logic rather than trying to emulate Unix on Windows (or vice versa).
* Write user-facing messages in clear, present tense: "Epithet now supports..." not "Epithet now supported..."

## Pragmatic incrementalism

* "Not overly generic"—prefer specific, composable logic over abstract frameworks.
* Evolve the design incrementally rather than attempting perfect upfront architecture.
* Document design decisions and trade-offs in design docs
* When uncertain, explore and iterate

## Production-grade engineering

* Test comprehensively, including edge cases, race conditions, and stress tests.
* Pay attention to what facilities already exist, and aim to reuse them.
* Getting the details right is really important!

## Documentation

* Use inline comments to explain "why," not just "what".
* Module-level documentation should explain purpose and responsibilities.
* Always use periods at the end of code comments.
* Never use title case in headings and titles. Always use sentence case.

## Project Overview

Epithet is an SSH certificate authority system that makes SSH certificates easy to use. The project is currently undergoing a v2 rewrite (see README.md for v2 architecture details).

Design notes, future ideas, and exploratory documents are kept in the `ideas/` directory for future reference.

## Commit message conventions

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.
This enables automatic version bumping via `svu next`.

**Format:** `<type>[optional scope]: <description>`

**Types and their version impact:**
- `fix:` → patch bump (0.6.0 → 0.6.1)
- `feat:` → minor bump (0.6.0 → 0.7.0)
- `feat!:` or `BREAKING CHANGE:` → major bump (0.6.0 → 1.0.0)
- `docs:`, `chore:`, `test:`, `refactor:` → no version bump

**Examples:**
- `fix: handle nil pointer in broker auth`
- `feat: add OIDC token refresh support`
- `feat!: change auth command protocol to use fd3`
- `docs: update README with new config format`
- `chore: update dependencies`

## Version control policy

**CRITICAL**: Do NOT create commits or interact with git to make new commits. The user will handle all commit creation.

You are welcome to:
- View commit history (`git log`, `git show`)
- Check git status (`git status`, `git diff`)
- View old commits and changes
- Stage files for review (`git add` to help user see what will be committed)

You must NOT:
- Create commits (`git commit`)
- Push changes (`git push`)
- Create branches (`git checkout -b`)
- Merge or rebase (`git merge`, `git rebase`)

The user prefers to review all changes and craft commit messages themselves.

## Task Management with yatl

**CRITICAL**: This project uses yatl (Yet Another Task List) for ALL task tracking. Do NOT use TodoWrite under any circumstances.

When working on tasks:
1. **Always use yatl** - Create tasks with `yatl new`, start with `yatl start`, close with `yatl close`
2. **Use yatl proactively** - For any non-trivial work (multiple steps, complex tasks), create yatl tasks immediately
3. **Track progress** - Use `yatl list` to show current work, `yatl ready` to find unblocked tasks, `yatl next` for suggested task
4. **Log progress** - Use `yatl log <id> "message"` to record progress throughout work
5. **Dependencies matter** - Use `yatl block` to track task dependencies when needed
6. **Never use TodoWrite** - The TodoWrite tool is disabled for this project
7. **ALWAYS close tasks when done** - When you finish implementing a task, immediately run `yatl close <id> --reason "..."`. Check git commits if unsure whether a task was already completed.

Example workflow:
```bash
# Start work on a feature
yatl new "Implement auth command protocol" --priority high --tags feature

# Track subtasks
yatl new "Parse netstring input from stdin" --tags task
yatl new "Invoke auth command and capture output" --tags task
yatl block <task-2-id> <task-1-id>  # task-2 is blocked by task-1

# Start working
yatl start <task-1-id>

# Log progress as you work
yatl log <task-1-id> "Found root cause, implementing fix"

# Close completed work
yatl close <task-1-id> --reason "Completed netstring parser"
```

## High-Level Architecture

Epithet is an SSH certificate management tool that creates on-demand SSH agents for outbound connections. The core concept is to replace traditional SSH key-based authentication with certificate-based authentication using per-connection agents.

**Implementation Status**: The v2 architecture is **complete and production-ready**. All protocols, communication paths, and policy logic are fully implemented. See "Current Development Status" section below for details.

### Terminology

- **Broker**: The daemon process started by `epithet agent`. It manages user authentication state, certificate lifecycle, and creates per-connection agent instances. The broker is the central coordinator for all epithet functionality on an endpoint. Each broker instance creates a unique directory under `~/.epithet/run/<instance-hash>/` containing its socket, agent sockets, and auto-generated SSH config.
- **Per-connection agents**: Individual in-process SSH agent instances (from `pkg/agent`), one per unique SSH connection (identified by %C hash). Each serves a single certificate via an agent socket at `~/.epithet/run/<instance-hash>/agent/%C`. Uses `golang.org/x/crypto/ssh/agent` for efficient in-process agent implementation (much lower overhead than spawning OpenSSH ssh-agent processes).
- **Auth command**: External command configured by the user (via `--auth` flag) that handles authentication with identity providers (SAML, OIDC, etc). The broker invokes this command to obtain authentication tokens. Can be a custom script or use the built-in `epithet auth oidc` command for OAuth2/OIDC providers.

### v2 Architecture (IMPLEMENTED)

The `epithet match` workflow implements 5 key steps (fully functional in `pkg/broker/broker.go:Match()`):

1. **Host pattern matching**: Check if the host should be handled by epithet at all (abort early if not)
2. **Certificate lookup**: Check for existing, unexpired certificate for the target user/host (with 5-second expiry buffer)
3. **Agent with existing cert**: If certificate exists, ensure agent socket at %C exists with that certificate
4. **Certificate request**: If no certificate exists, request one (including authentication), then go to step 3
5. **Expiry cleanup**: Background cleanup deletes expired agent sockets every 30 seconds

**Certificate Swapping**: The broker implements intelligent certificate reuse via `Agent.UseCredential()` - when a certificate expires, the broker can swap a fresh certificate into the existing agent without changing the socket path. This provides seamless renewal for long-running SSH sessions.

### Command Structure

**Implementation**: The `epithet` binary uses `alecthomas/kong` for command-line parsing, with CUE-based config file loading supporting YAML, CUE, and JSON formats with multi-file unification. All commands are fully implemented and production-ready.

- **`epithet match --host %h --port %p --user %r --hash %C [--jump %j] [--broker <path>]`**:
  - **Status**: ✅ Fully implemented (`cmd/epithet/match.go`)
  - Invoked by OpenSSH Match exec during connection establishment
  - Implements 5-step certificate/agent workflow via RPC to broker
  - Communicates with the broker (started by `epithet agent`) to request certificates
  - Returns success/failure to OpenSSH to control whether connection proceeds
  - Optional `--broker` flag specifies broker socket path (for multiple broker instances)

- **`epithet agent --ca-url <url> --auth <command> [--config <file>]`**:
  - **Status**: ✅ Fully implemented (`cmd/epithet/agent.go`, `pkg/broker/`)
  - Starts the broker daemon with RPC server on Unix domain socket
  - Required flags (can be set in config file with mustache template support):
    - `--ca-url`: CA URL(s) - repeatable for multi-CA failover. Optionally prefix with `priority=N:` (e.g., `priority=50:https://backup.example.com`); plain URLs default to priority 100. Higher priority CAs are tried first; circuit breakers skip failed CAs.
    - `--auth`: Command to invoke for user authentication (can use templates)
  - Host patterns are obtained dynamically from CA discovery (no static `--match` flag needed)
  - Auto-generates SSH config file at `~/.epithet/run/<instance-hash>/ssh-config.conf`
  - The broker maintains (with proper concurrency controls):
    - Map of connection hash → per-connection agent instance (`pkg/agent.Agent`)
    - Map of user identity → authentication state (token + state blob)
    - Certificate store with policy-based matching and expiration tracking
  - Creates in-process SSH agent instances for each unique connection (low memory overhead)
  - Manages authentication state and token refresh with retry logic
  - Graceful shutdown with proper cleanup

- **`epithet ca --policy <url> --key <path> --address <addr>`**:
  - **Status**: ✅ Fully implemented (`cmd/epithet/ca.go`, `pkg/ca/`, `pkg/caserver/`)
  - Runs the CA server as a standalone HTTP service
  - Listens on specified address (default 0.0.0.0:8080)
  - Reads CA private key from file
  - Validates certificate requests against policy server with cryptographic verification

- **`epithet auth oidc --issuer <url> --client-id <id> [--client-secret <secret>]`**:
  - **Status**: ✅ Fully implemented (`cmd/epithet/auth_oidc.go`)
  - Built-in OIDC/OAuth2 authentication plugin
  - Implements the auth command protocol (stdin/stdout/fd3)
  - Supports PKCE for public clients (no client secret needed)
  - Handles token refresh automatically via refresh tokens
  - Works with Google Workspace, Okta, Azure AD, and other OIDC providers
  - Uses browser-based authentication flow with local callback server
  - See `examples/google-workspace/` for setup guide

### Core Architecture

The system consists of four main components (all fully implemented):

1. **CA Server** (`pkg/ca`, `pkg/caserver`, `cmd/epithet-ca`): The certificate authority that signs SSH certificates. Accepts tokens via `Authorization: Bearer` header. Uses shape-based routing: empty body for hello requests (token validation only), or full body with publicKey+connection for certificate requests. Validates tokens against a policy server using cryptographic verification (SSH signature via Rekor/Sigstore over the request body), then signs public keys to create certificates. Returns certificates with policy metadata (hostPattern) for intelligent reuse.

2. **CA Client** (`pkg/caclient`): HTTP client library that requests certificates from the CA server. Sends tokens in the `Authorization: Bearer` header. Provides `GetCert()` for certificate requests and `Hello()` for token validation without requesting a certificate. Includes domain-specific error types for different failure modes (InvalidTokenError, PolicyDeniedError, ConnectionNotHandledError, CAUnavailableError). Supports multi-CA failover with circuit breakers.

3. **Broker** (`pkg/broker`): The daemon process managing certificate lifecycle and authentication on endpoints. Orchestrates auth commands (stdin/stdout/fd3 protocol), CA requests with retry logic, and per-connection agent instances. Uses net/rpc over Unix domain socket for communication with `epithet match`. Implements policy-based certificate reuse and automatic expiry cleanup.

4. **Per-connection Agents** (`pkg/agent`): In-process SSH agent implementation using `golang.org/x/crypto/ssh/agent`. One agent instance per unique connection, each exposing a Unix socket at `~/.epithet/run/<instance-hash>/agent/%C`. Provides low-overhead SSH agent protocol implementation without spawning external processes. Supports atomic certificate swapping via `UseCredential()`.

### Authentication Mechanism

The broker uses an external **auth command** to obtain authentication tokens. This design allows epithet to work with any identity provider (SAML, OIDC, Kerberos, custom) without the broker needing to understand authentication protocols.

**Implementation Status**: ✅ Fully implemented in `pkg/broker/auth.go` with comprehensive test coverage (18 tests). The built-in `epithet auth oidc` command (`cmd/epithet/auth_oidc.go`) provides production-ready OAuth2/OIDC support.

#### Auth Command Protocol

The broker communicates with auth plugins using a simple **file descriptor protocol** (fully implemented). This protocol requires no encoding/decoding - plugins work with raw bytes.

**Protocol:**
- **stdin (fd 0)**: State bytes from previous invocation (empty on first call)
- **stdout (fd 1)**: Authentication token (raw bytes)
- **fd 3**: New state bytes to persist for next invocation (max 10 MiB)
- **stderr (fd 2)**: Human-readable error messages (on failure)
- **Exit code**: 0 = success, non-zero = failure

**State Management:**
- State is **completely opaque** to the broker (arbitrary byte blob, max 10 MiB)
- Auth plugin owns session management (refresh tokens, token expiry, etc)
- Broker stores state in memory and passes it to next invocation
- State never touches disk (security: refresh tokens remain in memory only)

**Protocol Flow:**

**Initial authentication (no prior state):**
```bash
# INPUT: stdin is empty
# Plugin performs authentication (browser flow, etc)
# OUTPUT: stdout = access token, fd 3 = refresh token blob
```

**Token refresh (with existing state):**
```bash
# INPUT: stdin = previous state blob (e.g., refresh token)
# Plugin uses refresh token to get new access token
# OUTPUT: stdout = new access token, fd 3 = updated state blob
```

**Authentication failure:**
```bash
# Plugin writes error to stderr and exits non-zero
# Broker presents error to user
```

**Example Implementations:**

**Bash:**
```bash
#!/bin/bash
# Read state from stdin
state=$(cat)

# Authenticate (using state if available)
if [ -n "$state" ]; then
    # Refresh flow
    token=$(curl -s "https://auth.example.com/refresh" -d "$state")
else
    # Initial auth flow
    token=$(do_browser_auth)
fi

# Output token to stdout
echo -n "$token"

# Output new state to fd 3
echo -n "$new_state_blob" >&3
```

**Python:**
```python
import sys, os

# Read state from stdin
state = sys.stdin.buffer.read()

# Authenticate
token, new_state = authenticate(state)

# Output token to stdout
sys.stdout.buffer.write(token)

# Output new state to fd 3
os.write(3, new_state)
```

**Go:**
```go
package main

import (
    "io"
    "os"
)

func main() {
    // Read state from stdin
    state, _ := io.ReadAll(os.Stdin)

    // Authenticate
    token, newState := authenticate(state)

    // Output token to stdout
    os.Stdout.Write(token)

    // Output new state to fd 3
    stateFd := os.NewFile(3, "state")
    defer stateFd.Close()
    stateFd.Write(newState)
}
```

**Design Properties:**
- Zero encoding/decoding burden for plugin authors
- Binary-safe (tokens and state can be arbitrary bytes)
- State never touches disk (security property)
- Simple to implement (basic file I/O in any language)
- Size-limited (10 MiB max state) to prevent memory exhaustion

#### Certificate Lifecycle with Short-Lived Certificates

**Key Timing Decision**: SSH certificates are **short-lived (2-10 minutes)** to enable real-time policy enforcement.

**Authentication vs Certificate Expiry:**
- **Auth sessions**: Long-lived (hours/days) via refresh tokens stored in state blob
- **SSH certificates**: Short-lived (2-10 minutes) for just-in-time authorization
- **Auth command calls**: Only when certificate expires (not proactively)

**Rationale for short certificate lifetime:**
- Minimal blast radius if certificate is stolen/compromised
- CA policy server evaluates "can this user access this host RIGHT NOW" for small values of now
- Time-bound access reduces risk in dynamic environments
- Stolen credentials have very limited window of usefulness

**User Experience:**
- First connection of the day: 2-5 seconds (browser auth flow)
- Subsequent connections (within refresh token lifetime): ~100-200ms (token refresh via auth command)
- After refresh token expires (e.g., 8 hours later): 2-5 seconds (full re-auth)

**Flow when epithet match is called:**

1. **Certificate exists and valid** (common case):
   - Broker returns immediately, no auth call, no CA request
   - SSH uses existing certificate from agent socket

2. **Certificate expired or missing**:
   - Broker looks up auth state for this user identity
   - Broker invokes auth command with state on stdin, fd 3 open for new state
   - Auth command uses refresh token to get fresh access token (~100ms)
   - Auth command outputs: token to stdout, updated state to fd 3
   - Broker calls CA: `request_certificate(token, connection_details)`
   - CA validates token and evaluates policy in real-time
   - CA returns certificate with 2-10 minute expiry
   - Broker stores certificate and updated auth state
   - Broker updates/creates agent socket with new certificate
   - SSH proceeds with fresh certificate

**Why no proactive refresh in v1:**
- Keeps protocol simple (tokens and state remain opaque)
- Proactive refresh would require auth command to communicate token expiry
- On-demand refresh latency (~100-200ms) is acceptable
- Can add `REFRESH_BEFORE <timestamp>` to protocol in future if needed

### Key Data Flow

1. User initiates SSH connection → OpenSSH Match exec calls `epithet match`
2. Broker checks if certificate exists and is valid for this connection hash
3. If expired/missing: Broker calls auth command with previous state blob
4. Auth command returns fresh token + updated state
5. Broker generates ephemeral keypair for this connection
6. Broker requests certificate from CA server with token and connection details
7. CA server validates token against policy server (external HTTP endpoint)
8. CA server evaluates real-time policy: "Can this user access this host as this user RIGHT NOW?"
9. CA server returns signed certificate with principals, expiration (2-10 min), and extensions
10. Broker stores certificate and auth state
11. Broker ensures per-connection agent socket exists with this certificate
12. SSH agent serves certificate via SSH agent protocol on the per-connection socket
13. OpenSSH uses certificate from agent socket to establish connection

### Important Types and Abstractions

- **`sshcert.RawPrivateKey`, `RawPublicKey`, `RawCertificate`**: Type-safe wrappers for SSH keys/certs in on-disk format (string-based)
- **`ca.CertParams`**: Policy response containing identity, principals, expiration, and extensions for a certificate
- **`policy.Connection`**: Connection details (%h, %p, %r, %C, %j) passed through Match → Broker → CA → Policy
- **`policy.Policy`**: Policy metadata (hostPattern) returned with certificates for intelligent reuse
- **`agent.Credential`**: Private key + certificate pair used by the agent
- **`caclient.InvalidTokenError`, `PolicyDeniedError`, `ConnectionNotHandledError`, `CAUnavailableError`**: Domain-specific error types for CA failures

### Broker → CA Protocol

**Protocol Status**: ✅ Fully implemented

The broker requests certificates from the CA server over HTTP. Authentication tokens are sent in the `Authorization` header, not the request body.

**Request Format** (from broker to CA):
```http
POST /path/to/ca HTTP/1.1
Content-Type: application/json
Authorization: Bearer <authentication-token>

{
  "publicKey": "ssh-ed25519 AAAA... user@host",
  "connection": {
    "localHost": "laptop.local",
    "remoteHost": "server.example.com",
    "remoteUser": "alice",
    "port": 22,
    "proxyJump": "",
    "hash": "abc123..."
  }
}
```

**Response Format** (from CA to broker):
```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "policy": {
    "hostPattern": "*.example.com"
  }
}
```

**Shape-Based Request Routing**:
The CA server routes requests based on the presence/absence of body fields:
- **Both fields present** (`publicKey` + `connection`): Certificate request (existing flow)
- **Both fields absent** (empty body `{}`): Hello request - validates token only, returns 200 on success
- **One field present**: Invalid request, returns 400 Bad Request

**Hello Request**:
The `Hello()` method in `pkg/caclient` validates a token without requesting a certificate:
```http
POST /path/to/ca HTTP/1.1
Content-Type: application/json
Authorization: Bearer <authentication-token>

{}
```
Returns 200 on success, or appropriate error (401, 403, 422, 5xx).

**Error Handling**:
- HTTP 401: Token is invalid/expired (broker should re-authenticate)
- HTTP 403: Token valid but policy denied access
- HTTP 422: Connection not handled by this CA/policy
- HTTP 5xx: CA unavailable (triggers circuit breaker failover to backup CAs)
- HTTP 4xx: Invalid request format

### CA → Policy Server Protocol

**Protocol Status**: ✅ Fully implemented
**Server Implementation**: ✅ Production-ready policy server (`epithet policy`) with OIDC token validation

The CA validates authentication tokens by calling an external policy server over HTTP. The CA's signature is sent in the `Authorization` header, computed over the entire request body.

**Request Format** (from CA to policy server):
```http
POST /policy HTTP/1.1
Content-Type: application/json
Authorization: Bearer <base64-ssh-signature-over-body>

{
  "token": "<base64url-encoded-authentication-token>",
  "connection": {
    "localHost": "laptop.local",
    "remoteHost": "server.example.com",
    "remoteUser": "alice",
    "port": 22,
    "proxyJump": "",
    "hash": "abc123..."
  }
}
```

**Response Format** (from policy server to CA):
```json
{
  "certParams": {
    "identity": "alice@example.com",
    "principals": ["alice", "admin"],
    "expiration": "5m",
    "extensions": {
      "permit-pty": "",
      "permit-agent-forwarding": ""
    }
  },
  "policy": {
    "hostPattern": "*.example.com"
  }
}
```

**Cryptographic Verification**:
- CA signs the **entire request body** (JSON bytes) using its SSH private key (Rekor/Sigstore SSH signing)
- Signature is sent in the `Authorization: Bearer` header
- Policy server verifies the signature using the CA's public key
- This prevents request tampering and ensures policy requests come from the legitimate CA

**Token Encoding**:
- Tokens are base64url-encoded in the request body (preserves arbitrary bytes from auth plugins)
- Policy server decodes the token before validation

**Error Handling**:
- HTTP 401: Token is invalid/expired (CA retries with fresh token from auth plugin)
- HTTP 403: Token valid but policy denied (CA returns PolicyDeniedError immediately)
- HTTP 422: Connection not handled by this CA/policy (CA returns ConnectionNotHandledError, broker fails match to let SSH fall through)
- HTTP 5xx: CA/policy server unavailable (CA returns CAUnavailableError)
- HTTP 4xx: Invalid request format (CA returns InvalidRequestError)

### Error Handling and Match Behavior

**IMPORTANT**: These design decisions affect how epithet interacts with SSH's Match exec behavior.

#### SSH Config Precedence
- SSH uses **first match wins** for configuration parameters
- More specific Match blocks should appear before general ones
- When a Match exec returns non-zero, that Match block doesn't apply and SSH continues to the next Match or default config

#### Match Failure Strategy
When epithet cannot obtain a certificate (auth failures, CA errors, agent creation failures):
1. **Log clear error to stderr** - User-friendly message explaining what went wrong (verbosity matching configured log level)
2. **Exit with non-zero status** - Fail the Match so SSH falls through to next config
3. **Allow SSH fallback** - Enables breakglass/escape hatch scenarios

**Rationale:**
- Enables breakglass accounts: users can have epithet Match blocks first, then special-case configs (e.g., `Match host *.example.com user breakglass` with specific IdentityFile)
- If epithet fails the Match, SSH can try other auth methods (default keys, other agents)
- Trade-off: May leak connection attempts to fallback systems, but this is acceptable to enable legitimate escape hatches
- Users who need strict security can configure SSH with no fallbacks after epithet Match blocks

**Recommended SSH Config Structure:**
```ssh_config
# Epithet handling - first so it gets priority
Match exec "epithet match --host %h --port %p --user %r --hash %C"
    IdentityAgent ~/.epithet/agent/%C

# Breakglass/special cases - after epithet
Match host *.example.com user breakglass
    IdentityFile ~/.ssh/breakglass_cert

# Default config last
```

**Multiple Concurrent Brokers:**
Epithet supports running multiple broker instances for different purposes (work vs personal, different CA servers, etc). Each broker needs a unique socket path. You can optionally add SSH `host` patterns for optimization (to skip broker calls for unrelated hosts), but this is not required since the broker checks discovery patterns dynamically:

```ssh_config
# Work connections (with optional host filter for optimization)
Match exec "epithet match --host %h --port %p --user %r --hash %C --broker ~/.epithet/work-broker.sock" host *.work.example.com
    IdentityAgent ~/.epithet/work-agent/%C

# Personal connections
Match exec "epithet match --host %h --port %p --user %r --hash %C --broker ~/.epithet/personal-broker.sock" host *.personal.example.com
    IdentityAgent ~/.epithet/personal-agent/%C
```

Start each broker with unique socket paths:
```bash
# Work broker (with primary and backup CAs)
# Host patterns come from CA discovery endpoint
epithet agent --broker ~/.epithet/work-broker.sock \
              --agent-dir ~/.epithet/work-agent/ \
              --ca-url https://work-ca.example.com \
              --ca-url 'priority=50:https://work-ca-backup.example.com' \
              --auth work-auth-plugin

# Personal broker (single CA)
epithet agent --broker ~/.epithet/personal-broker.sock \
              --agent-dir ~/.epithet/personal-agent/ \
              --ca-url https://personal-ca.example.com \
              --auth personal-auth-plugin
```

#### CA Error Handling

**HTTP 401 Unauthorized** - Token is invalid or expired:
1. Clear the current token
2. Invoke auth plugin (may use refresh token from state or do full re-auth)
3. Retry cert request with new token
4. Limit retries (2-3 attempts) to prevent infinite loops with buggy auth plugins
5. Use immediate retries (no backoff) - if persistent issue, user will retry SSH connection
6. If retries exhausted, fail the Match with clear error

**HTTP 403 Forbidden** - Authentication succeeded but policy denied the request:
1. Keep the token (it's valid, just not authorized for this connection)
2. Fail the Match with clear error explaining policy denial
3. Do not retry (policy decision is intentional)

**HTTP 422 Unprocessable Content** - CA/policy server does not handle this connection:
1. Keep the token (it's valid, just not for this CA)
2. Fail the Match with clear error
3. Do not retry (this CA simply doesn't handle this connection type/host)
4. SSH will fall through to other auth methods (different CA, password, breakglass key, etc.)

**HTTP 5xx Server Error** - Transient CA/policy server issue:
1. Keep the token
2. Fail the Match with clear error
3. User can retry SSH connection

**HTTP 4xx Client Error** (other than 401/403):
1. Keep the token
2. Fail the Match with clear error
3. Do not retry (likely a permanent client-side issue)

#### Auth Plugin Error Handling

**Exit 0 with error field** - User-facing auth failure (cancelled flow, MFA failed, invalid credentials):
1. Keep the existing state (don't clear it)
2. Fail the Match with the error message from auth plugin
3. User can retry SSH connection when ready

**Non-zero exit** - Unexpected error (network issue, plugin crash, etc):
1. Keep the existing state
2. Retry up to limit (same as CA 401 retry limit)
3. If retries exhausted, fail the Match with error
4. Use immediate retries (no backoff)

#### Certificate and Agent Management

**Certificate Storage:**
- Always store certificates obtained from CA, even if agent creation later fails
- Certificates are bound to policies (hostPattern), not individual agents
- Multiple agents (different connection hashes) may reuse the same certificate if policy matches
- Keep certificates in store even on agent creation failures (cert is still valid)

**Agent Creation Failures:**
- Typically local system issues (permissions, disk space, socket directory problems)
- Keep certificate in store (it's valid, may work on retry)
- Fail the Match with clear error explaining the local issue (not a cert/auth problem)
- User can fix local issue and retry

### Configuration and SSH Integration

#### Auto-Generated SSH Config

When `epithet agent` starts, it automatically generates an SSH config file at `~/.epithet/run/<instance-hash>/ssh-config.conf` that you can include in your `~/.ssh/config`:

```ssh_config
# Generated by epithet agent
Match exec "epithet match --broker /home/user/.epithet/run/abc123/broker.sock --host %h --port %p --user %r --hash %C --jump %j" host *.example.com
    IdentityAgent /home/user/.epithet/run/abc123/agent/%C
```

**Usage**: Add this to your `~/.ssh/config`:
```ssh_config
Include ~/.epithet/run/*/ssh-config.conf
```

This automatically updates when you start new broker instances and ensures the correct broker socket and agent paths are used.

#### Config File Format

Epithet uses structured config files in YAML, CUE, or JSON format. Config sections mirror the CLI command structure.

**Location**: `~/.epithet/*.yaml` (or `.yml`, `.cue`, `.json`)

**Multi-file unification**: All config files in `~/.epithet/` are loaded and merged using CUE's `Value.Unify()`. This allows splitting config across multiple files (e.g., `base.yaml`, `work.yaml`). Conflicting values (same field, different values) cause an error at startup.

**Example** (`~/.epithet/config.yaml`):
```yaml
# Global flags
insecure: false
verbose: 1

# Agent configuration
agent:
  match:
    - "*.work.example.com"
    - "*.dev.example.com"
  ca_url:
    - "https://ca-primary.example.com"               # Default priority (100)
    - "priority=50:https://ca-backup.example.com"    # Lower priority = backup
  auth: epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID
```

**Config key naming**: Use `snake_case` in config files (e.g., `ca_url`), which maps to CLI flags with `kebab-case` (e.g., `--ca-url`).

## Development Commands

### Building
```bash
make build          # Build all binaries (epithet, epithet-ca)
make epithet-ca     # Build only the CA server
go build ./cmd/epithet  # Build the epithet CLI
```

### Testing
```bash
make test           # Run all tests
go test ./...       # Alternative: run all tests directly

# Run specific package tests
go test ./pkg/agent
go test ./pkg/ca
go test ./pkg/caserver
go test ./pkg/caclient
go test ./pkg/sshcert

# Run specific test
go test -v ./pkg/agent -run TestBasics
go test -v ./pkg/ca -run TestCA_Sign
```

### Code Generation
```bash
make generate       # Generate protobuf code (internal/agent/agent.pb.go)
go generate ./...   # Alternative: run go generate
```

The project uses protobuf for agent communication. Generated files are in `internal/agent/agent.pb.go` and must be regenerated after proto changes.

### Cleanup
```bash
make clean          # Clean build artifacts and test cache
make clean-all      # Clean everything including generated code and module cache
```

## Testing Infrastructure

**Status**: ✅ Comprehensive test coverage across all components

The project includes:
- **Unit tests**: 12 test files covering all major packages (agent, broker, auth, CA, certs, caclient, caserver, sshcert, oidc)
- **Integration tests**: `test/sshd/broker_test.go` provides full end-to-end testing with real sshd server, validating the complete flow: broker → auth → CA → policy → certificate → agent → SSH connection
- **Test infrastructure**: `test/sshd/` package provides utilities for running real SSH servers in tests
- **Mock auth scripts**: Example bash scripts for testing broker flows without real identity providers
- **Mock policy server**: Test implementations for validating CA flows

Run all tests with `make test` or `go test ./...`.

### Manual local testing with binaries

To test the full stack with actual binaries (not Go test harness), use a mock OIDC server:

**1. Install mock OIDC server:**
```bash
# Using uvx (recommended) or pip
uvx oidc-provider-mock --port 9400
```

**2. Create test directory and keys:**
```bash
mkdir -p /tmp/epithet-test/auth_principals
ssh-keygen -t ed25519 -f /tmp/epithet-test/ca-key -N ""
ssh-keygen -t ed25519 -f /tmp/epithet-test/ssh_host_key -N ""
```

**3. Create policy config (`/tmp/epithet-test/policy.yaml`):**
```yaml
policy:
  ca_pubkey: "/tmp/epithet-test/ca-key.pub"
  oidc:
    issuer: "http://localhost:9400"
    client_id: "test-client"
  defaults:
    expiration: "5m"
    extensions:
      permit-pty: ""
    allow:
      YOUR_USERNAME: [admin]
  users:
    "sub": [admin]        # Mock OIDC returns "sub" or username
    "YOUR_USERNAME": [admin]
  hosts:
    "*":
      allow:
        YOUR_USERNAME: [admin]
```

**4. Create sshd config (`/tmp/epithet-test/sshd_config`):**
```
Port 2222
PasswordAuthentication no
PubkeyAuthentication yes
StrictModes no
UsePAM no
HostKey /tmp/epithet-test/ssh_host_key
TrustedUserCAKeys /tmp/epithet-test/ca-key.pub
AuthorizedPrincipalsFile /tmp/epithet-test/auth_principals/%u
```

**5. Create principals file:**
```bash
echo "YOUR_USERNAME" > /tmp/epithet-test/auth_principals/YOUR_USERNAME
```

**6. Start components (5 terminals):**
```bash
# Terminal 1: Mock OIDC
uvx oidc-provider-mock --port 9400

# Terminal 2: Policy server
./epithet policy --config /tmp/epithet-test/policy.yaml --listen 127.0.0.1:9999 --insecure -vv

# Terminal 3: CA server
./epithet ca --key /tmp/epithet-test/ca-key --policy http://127.0.0.1:9999 --listen 127.0.0.1:8080 --insecure -vv

# Terminal 4: sshd (debug mode, single-threaded)
/usr/sbin/sshd -d -D -f /tmp/epithet-test/sshd_config

# Terminal 5: Agent (use --run-dir to avoid ~/.epithet)
./epithet agent \
  --ca-url http://127.0.0.1:8080 \
  --run-dir /tmp/epithet-test/run \
  --auth "./epithet auth oidc --issuer http://localhost:9400 --client-id test-client --client-secret test-secret --browser 'open -a \"Google Chrome\"' --insecure" \
  --insecure -vv
```

**7. Test SSH:**
```bash
# Create SSH config with Include
echo 'Include /tmp/epithet-test/run/*/ssh-config.conf' > /tmp/epithet-test/ssh_config

# SSH (first time opens browser for OIDC login)
ssh -F /tmp/epithet-test/ssh_config \
  -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
  -p 2222 YOUR_USERNAME@localhost
```

**Notes:**
- Mock OIDC requires `--client-secret` (doesn't support PKCE)
- sshd in `-d` mode exits after one connection - restart for each test
- The `Include` wildcard pattern finds the agent config automatically
- Use `--browser` to specify a browser (e.g., `--browser 'open -a "Google Chrome"'` on macOS)
- Use `--run-dir` to place runtime files in a custom directory

## Project Structure Notes

- Currently on branch `v2.go` with v2 implementation complete
- Main branch for PRs is `master`
- The Makefile defines all standard development workflows
- Uses Go 1.25.0 with modules
- Key dependencies:
  - `golang.org/x/crypto/ssh` - SSH agent and certificate implementation
  - `github.com/sigstore/sigstore/pkg/signature` - SSH signature verification for policy server protocol
  - `alecthomas/kong` - Command-line parsing
  - `cuelang.org/go/cue` - Configuration loading with multi-file unification
  - `cbroglie/mustache` - Template rendering in auth commands
  - `coreos/go-oidc/v3` - OIDC authentication
  - `golang.org/x/oauth2` - OAuth2 flows

## Important Constants and Limits

- `caserver.RequestBodySizeLimit = 8192`: Maximum HTTP request body size for CA requests
- `pkg/broker/auth.go:maxStateSizeBytes = 10 MiB`: Maximum auth state size
- `pkg/broker/broker.go:maxRetries = 3`: Maximum retry attempts for CA 401 and auth failures
- `pkg/broker/broker.go:expiryBuffer = 5 seconds`: Safety margin for certificate expiry checks
- `pkg/broker/broker.go:cleanupInterval = 30 seconds`: Frequency of expired agent cleanup

### Integration with OpenSSH

Epithet integrates with OpenSSH via auto-generated config files. When you start `epithet agent`, it creates an SSH config file at `~/.epithet/run/<instance-hash>/ssh-config.conf`:

```ssh_config
Match exec "epithet match --host %h --port %p --user %r --hash %C --jump %j --broker ~/.epithet/run/<hash>/broker.sock"
    IdentityAgent ~/.epithet/run/<hash>/agent/%C
```

Note: The SSH config uses `Match exec` only (no `host` filter). The broker dynamically fetches host patterns from CA discovery and returns non-zero for hosts that don't match, allowing SSH to fall through to other configuration.

Add this to your `~/.ssh/config` to use it:
```ssh_config
Include ~/.epithet/run/*/ssh-config.conf
```

The `%C` token represents a hash of the connection parameters (`%l%h%p%r%j`: local hostname, remote hostname, port, username, and ProxyJump), ensuring each unique connection gets its own agent socket. The SSH config uses `Match exec` only - the broker dynamically fetches host patterns from CA discovery and returns non-zero for hosts that don't match, allowing SSH to fall through to other config.

### Current Development Status

**v2 is complete and production-ready!** 🎉

All core components of the v2 architecture (described in README.md) are fully implemented, tested, and functional. The system is ready for production deployment.

#### ✅ Fully Implemented Components

**1. Broker with Auth Command Protocol** (`pkg/broker/`):
   - ✅ Auth command invocation with stdin/stdout/fd3 protocol (`auth.go`)
   - ✅ Auth state storage with 10 MiB limit enforcement
   - ✅ Certificate store with policy-based matching (`certs.go`)
   - ✅ Token refresh on certificate expiry with retry logic
   - ✅ Comprehensive error handling for CA and auth failures
   - ✅ 18 unit tests covering all auth flows
   - ✅ Mustache template support in config files

**2. Match Command** (`cmd/epithet/match.go`):
   - ✅ Full argument parsing (`--host`, `--port`, `--user`, `--hash`, `--jump`, `--broker`)
   - ✅ RPC communication with broker over Unix domain socket
   - ✅ Complete 5-step certificate validation workflow
   - ✅ Host pattern eligibility checking
   - ✅ Proper exit codes for OpenSSH Match exec integration

**3. Broker ↔ CA Integration** (`pkg/broker/broker.go`, `pkg/caclient/`):
   - ✅ Certificate request flow: auth token → CA → signed certificate
   - ✅ Connection details passed to CA for principal determination
   - ✅ Domain-specific error types (InvalidTokenError, PolicyDeniedError, ConnectionNotHandledError, CAUnavailableError)
   - ✅ Retry logic for HTTP 401 (token expired, up to 3 attempts)
   - ✅ No retry for HTTP 403 (policy denial is intentional)
   - ✅ No retry for HTTP 422 (connection not handled, let SSH fall through)
   - ✅ Certificate storage with expiry tracking

**4. Broker ↔ Agent Management** (`pkg/broker/broker.go`, `pkg/agent/`):
   - ✅ Per-connection agent creation using `pkg/agent.Agent`
   - ✅ Map of connection hash (%C) → agent instance with expiry
   - ✅ Agent socket paths at `~/.epithet/run/<instance-hash>/agent/%C`
   - ✅ Certificate swapping/renewal via `Agent.UseCredential()`
   - ✅ Automatic cleanup of expired agents (every 30 seconds)
   - ✅ Graceful shutdown with proper resource cleanup

**5. CA and Policy Server** (`pkg/ca/`, `pkg/caserver/`, `pkg/policyserver/`):
   - ✅ Standalone CA server (`epithet ca`)
   - ✅ Policy server protocol with cryptographic verification (SSH signatures)
   - ✅ Production policy server with OIDC validation (`epithet policy`)
   - ✅ Error code propagation (401, 403, 5xx, 4xx)
   - For AWS Lambda deployment, see [epithet-aws](https://github.com/epithet-ssh/epithet-aws)

**6. Authentication** (`cmd/epithet/auth_oidc.go`):
   - ✅ Built-in OIDC/OAuth2 authentication
   - ✅ PKCE support for public clients
   - ✅ Token refresh with refresh tokens
   - ✅ Browser-based auth flow with local callback
   - ✅ Works with Google Workspace, Okta, Azure AD

**7. Infrastructure**:
   - ✅ Match pattern evaluation (glob patterns with `*` wildcard)
   - ✅ Comprehensive error handling throughout
   - ✅ Auto-generated SSH config files
   - ✅ Config file support with mustache templates
   - ✅ Multiple concurrent broker support
   - ✅ Proper logging and error messages
   - ✅ Graceful shutdown and cleanup
   - ✅ Full end-to-end integration tests

#### ✅ Current Status: Production Ready

**v2 is complete and production-ready!** All critical components are fully implemented:

- ✅ Certificate matching with HostUsers (matches host AND remote user)
- ✅ Production policy server with OIDC token validation (`epithet policy`)
- ✅ All protocols and communication paths working
- ✅ Auth command protocol with state management
- ✅ OIDC authentication with token refresh
- ✅ Certificate signing and SSH agent integration
- ✅ Multi-user scenarios supported
- ✅ Full end-to-end integration tests

**Minor remaining tasks**:
- Connection details in auth templates (`pkg/broker/broker.go`) - auth command mustache templates don't yet receive connection details (%h, %p, %r, %C)

### Available Examples

The `examples/` directory contains deployment guides and reference implementations:

- **`examples/bash_auth_example.bash`**: Reference bash auth plugin demonstrating the stdin/stdout/fd3 protocol
- **`examples/epithet.config.example`**: Sample config file in YAML format (also supports CUE and JSON)
- **`examples/google-workspace/`**: OIDC setup guide for Google Workspace integration (referenced in code)
- **`examples/README.md`**: Overview of deployment options and architecture choices

For AWS Lambda deployment, see the [epithet-aws](https://github.com/epithet-ssh/epithet-aws) repository.

These examples demonstrate real-world usage patterns and serve as templates for custom deployments.
