# CLAUDE.md

**Note**: This project uses [bd (beads)](https://github.com/steveyegge/beads) for issue tracking. Use `bd` commands instead of markdown TODOs. See AGENTS.md for workflow details.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Epithet is an SSH certificate authority system that makes SSH certificates easy to use. The project is currently undergoing a v2 rewrite (see README.md for v2 architecture details).

## Version Control Policy

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

## Task Management with bd

**CRITICAL**: This project uses bd (beads) for ALL task tracking. Do NOT use TodoWrite under any circumstances.

When working on tasks:
1. **Always use bd** - Create issues with `bd create`, update with `bd update`, close with `bd close`
2. **Use bd proactively** - For any non-trivial work (multiple steps, complex tasks), create bd issues immediately
3. **Track progress** - Use `bd list` to show current work, `bd ready` to find unblocked tasks
4. **Dependencies matter** - Use `bd dep add` to track task dependencies when needed
5. **Never use TodoWrite** - The TodoWrite tool is disabled for this project

Example workflow:
```bash
# Start work on a feature
bd create "Implement auth command protocol" --type feature

# Track subtasks
bd create "Parse netstring input from stdin" --type task
bd create "Invoke auth command and capture output" --type task
bd dep add TASK-2 TASK-1  # TASK-2 depends on TASK-1

# Update progress
bd update TASK-1 --status in-progress
bd update TASK-1 --status done

# Close completed work
bd close TASK-1 "Completed netstring parser"
```

## High-Level Architecture

Epithet is an SSH certificate management tool that creates on-demand SSH agents for outbound connections. The core concept is to replace traditional SSH key-based authentication with certificate-based authentication using per-connection agents.

**Implementation Status**: The v2 architecture has all **mechanisms** implemented (protocols, communication paths, token flow), but has **critical gaps in policy logic** that prevent production use. Specifically: certificate matching only considers hostname (not user/identity), and there's no real policy server (only a trivial test stub). See "Current Development Status" section below for details.

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

**Implementation**: The `epithet` binary uses `alecthomas/kong` for command-line parsing, with a custom KVLoader for config file support. All commands are fully implemented and production-ready.

- **`epithet match --host %h --port %p --user %r --hash %C [--jump %j] [--broker <path>]`**:
  - **Status**: ✅ Fully implemented (`cmd/epithet/match.go`)
  - Invoked by OpenSSH Match exec during connection establishment
  - Implements 5-step certificate/agent workflow via RPC to broker
  - Communicates with the broker (started by `epithet agent`) to request certificates
  - Returns success/failure to OpenSSH to control whether connection proceeds
  - Optional `--broker` flag specifies broker socket path (for multiple broker instances)

- **`epithet agent --match <pattern> --ca-url <url> --auth <command> [--config <file>]`**:
  - **Status**: ✅ Fully implemented (`cmd/epithet/agent.go`, `pkg/broker/`)
  - Starts the broker daemon with RPC server on Unix domain socket
  - Required flags (can be set in config file with mustache template support):
    - `--match`: Repeatable patterns defining which hosts epithet should handle
    - `--ca-url`: URL of the certificate authority
    - `--auth`: Command to invoke for user authentication (can use templates)
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

- **`epithet aws ca --secret-arn <arn> --policy-url <url>`**:
  - **Status**: ✅ Fully implemented (`cmd/epithet/aws.go`)
  - Runs the CA server as an AWS Lambda function
  - Retrieves CA private key from AWS Secrets Manager
  - Designed for serverless deployment (see `examples/aws-lambda/`)
  - Set `EPITHET_CMD=aws ca` environment variable to auto-invoke this command in Lambda

- **`epithet auth oidc --issuer <url> --client-id <id> [--client-secret <secret>]`**:
  - **Status**: ✅ Fully implemented (`cmd/epithet/auth_oidc.go`)
  - Built-in OIDC/OAuth2 authentication plugin
  - Implements the auth command protocol (stdin/stdout/fd3)
  - Supports PKCE for public clients (no client secret needed)
  - Handles token refresh automatically via refresh tokens
  - Works with Google Workspace, Okta, Azure AD, and other OIDC providers
  - Uses browser-based authentication flow with local callback server
  - See `examples/google-workspace/` for setup guide

- **`epithet dev policy --mode <allow-all|deny-all> --ca-public-key <key|url|file> --principals <p1,p2,...>`**:
  - **Status**: ✅ Implemented as trivial test stub (`cmd/epithet/dev.go`)
  - **Purpose**: Local testing and demonstrating the policy server protocol only
  - **Modes**: allow-all (always approves with hardcoded principals/identity), deny-all (always rejects)
  - **Does NOT**: Parse tokens, validate with identity provider, make real authorization decisions
  - **Limitations**: Returns fixed principals for all requests, always returns HostPattern="*"
  - **Not suitable for production** - see "Critical Gaps" section below
  - Useful for understanding the policy server HTTP protocol and testing certificate flows

### Core Architecture

The system consists of four main components (all fully implemented):

1. **CA Server** (`pkg/ca`, `pkg/caserver`, `cmd/epithet-ca`): The certificate authority that signs SSH certificates. It validates tokens against a policy server using cryptographic verification (SSH signature via Rekor/Sigstore), then signs public keys to create certificates. Returns certificates with policy metadata (hostPattern) for intelligent reuse.

2. **CA Client** (`pkg/caclient`): HTTP client library that requests certificates from the CA server by submitting tokens, public keys, and connection details. Provides domain-specific error types for different failure modes (InvalidTokenError, PolicyDeniedError, CAUnavailableError).

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
- **`caclient.InvalidTokenError`, `PolicyDeniedError`, `CAUnavailableError`**: Domain-specific error types for CA failures

### Policy Server Protocol

**Protocol Status**: ✅ CA-side implementation complete in `pkg/ca/ca.go:RequestPolicy()`
**Server Implementation**: ⚠️ Only trivial test stub exists (`epithet dev policy`), no production-ready policy server

The CA validates authentication tokens by calling an external policy server over HTTP. The policy server is expected to verify the token and return certificate parameters.

**Request Format** (from CA to policy server):
```json
{
  "token": "authentication-token-from-user",
  "signature": "base64-ssh-signature-from-CA-private-key",
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
- CA signs the authentication token using its SSH private key (Rekor/Sigstore SSH signing)
- Policy server verifies the signature using the CA's public key
- This prevents token replay attacks and ensures policy requests come from the legitimate CA

**Error Handling**:
- HTTP 401: Token is invalid/expired (CA retries with fresh token from auth plugin)
- HTTP 403: Token valid but policy denied (CA returns PolicyDeniedError immediately)
- HTTP 5xx: CA/policy server unavailable (CA returns CAUnavailableError)
- HTTP 4xx: Invalid request format (CA returns InvalidRequestError)

**Current Implementation**: `epithet dev policy` demonstrates the HTTP protocol but is only a trivial test stub (allow-all/deny-all modes with hardcoded principals). A production policy server needs to validate tokens, query identity providers, and make real authorization decisions. See "Critical Gaps" section.

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
Epithet supports running multiple broker instances for different purposes (work vs personal, different CA servers, etc). Each broker needs a unique socket path:

```ssh_config
# Work connections
Match exec "epithet match --host %h --port %p --user %r --hash %C --broker ~/.epithet/work-broker.sock" host *.work.example.com
    IdentityAgent ~/.epithet/work-agent/%C

# Personal connections
Match exec "epithet match --host %h --port %p --user %r --hash %C --broker ~/.epithet/personal-broker.sock" host *.personal.example.com
    IdentityAgent ~/.epithet/personal-agent/%C
```

Start each broker with unique socket paths:
```bash
# Work broker
epithet agent --broker ~/.epithet/work-broker.sock \
              --agent-dir ~/.epithet/work-agent/ \
              --match '*.work.example.com' \
              --ca-url https://work-ca.example.com \
              --auth work-auth-plugin

# Personal broker
epithet agent --broker ~/.epithet/personal-broker.sock \
              --agent-dir ~/.epithet/personal-agent/ \
              --match '*.personal.example.com' \
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

Epithet uses a simple key-value config file format (via KVLoader) that supports:
- One flag per line: `flag-name value`
- Repeatable flags: List the flag multiple times
- Mustache templates: Use `{{variable}}` in values (currently supports built-in functions like `{{ca_public_key}}`)
- Comments: Lines starting with `#`

**Example** (`~/.config/epithet/agent.conf`):
```
# Epithet agent configuration
match *.work.example.com
match *.dev.example.com
ca-url https://ca.example.com
auth epithet auth oidc --issuer https://accounts.google.com --client-id {{google_client_id}}
```

**Load config**:
```bash
epithet agent --config ~/.config/epithet/agent.conf
```

**Mustache Template Support**:
- The `--auth` flag supports mustache templates for dynamic command construction
- Currently only built-in functions are supported (like `{{ca_public_key}}` for fetching CA public key)
- Future: Connection details (%h, %p, %r, %C) passed to templates (TODO at `pkg/broker/broker.go:198`)

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

## Project Structure Notes

- Currently on branch `v2.go` with v2 implementation complete
- Main branch for PRs is `master`
- The Makefile defines all standard development workflows
- Uses Go 1.25.0 with modules
- Key dependencies:
  - `golang.org/x/crypto/ssh` - SSH agent and certificate implementation
  - `github.com/sigstore/sigstore/pkg/signature` - SSH signature verification for policy server protocol
  - `alecthomas/kong` - Command-line parsing
  - `cbroglie/mustache` - Template rendering in config files
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
Match exec "epithet match --broker ~/.epithet/run/<hash>/broker.sock --host %h --port %p --user %r --hash %C --jump %j" host <patterns>
    IdentityAgent ~/.epithet/run/<hash>/agent/%C
```

Add this to your `~/.ssh/config` to use it:
```ssh_config
Include ~/.epithet/run/*/ssh-config.conf
```

The `%C` token represents a hash of the connection parameters (`%l%h%p%r%j`: local hostname, remote hostname, port, username, and ProxyJump), ensuring each unique connection gets its own agent socket. The Match exec pattern includes the host patterns from `--match` flags to avoid unnecessary broker calls.

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
   - ✅ Domain-specific error types (InvalidTokenError, PolicyDeniedError, CAUnavailableError)
   - ✅ Retry logic for HTTP 401 (token expired, up to 3 attempts)
   - ✅ No retry for HTTP 403 (policy denial is intentional)
   - ✅ Certificate storage with expiry tracking

**4. Broker ↔ Agent Management** (`pkg/broker/broker.go`, `pkg/agent/`):
   - ✅ Per-connection agent creation using `pkg/agent.Agent`
   - ✅ Map of connection hash (%C) → agent instance with expiry
   - ✅ Agent socket paths at `~/.epithet/run/<instance-hash>/agent/%C`
   - ✅ Certificate swapping/renewal via `Agent.UseCredential()`
   - ✅ Automatic cleanup of expired agents (every 30 seconds)
   - ✅ Graceful shutdown with proper resource cleanup

**5. CA and Policy Server** (`pkg/ca/`, `pkg/caserver/`):
   - ✅ Standalone CA server (`epithet ca`)
   - ✅ AWS Lambda CA deployment (`epithet aws ca`)
   - ✅ Policy server protocol with cryptographic verification (SSH signatures)
   - ✅ Development policy server (`epithet dev policy`)
   - ✅ Error code propagation (401, 403, 5xx, 4xx)

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

#### ⚠️ Critical Gaps (Blocking Production Use)

1. **Certificate matching is incomplete** (`pkg/broker/certs.go`, `pkg/policy/policy.go`):
   - **Problem**: Certificates only match on hostname (via `Policy.HostPattern`)
   - **Missing**: Matching on remote user, auth identity, or certificate principals
   - **Impact**: Multiple users connecting to the same host will reuse the same certificate
   - **Example**: Alice gets cert with principal "alice" for server.example.com, then Bob connects to server.example.com and reuses Alice's cert (which will fail because SSH needs principal "bob")
   - **Needed**: Policy needs to include user/identity dimensions, and certificate lookup must validate principals match the connection

2. **No useful policy server implementation**:
   - **What exists**: `epithet dev policy` is a trivial test stub (allow-all or deny-all mode)
   - **What it doesn't do**:
     - Parse or validate the authentication token content
     - Verify token with the identity provider (OIDC provider, etc.)
     - Make real authorization decisions (check group membership, permissions, etc.)
     - Return appropriate principals based on user identity and target system
     - Implement realistic policies ("users in group X can access hosts Y as principals Z")
   - **Impact**: Cannot make real-world authorization decisions
   - **Needed**: Production policy server that validates tokens, queries directory services, and makes authorization decisions

3. **Connection details in auth templates** (`pkg/broker/broker.go:198`):
   - Auth command mustache templates don't yet receive connection details (%h, %p, %r, %C)
   - Lower priority than the above issues

#### 🚧 Current Status: Functional Prototype

The system has all the **mechanisms** working (protocols, communication, token flow, certificate signing), but lacks **complete policy logic** for production use:

**What works**:
- ✅ All protocols and communication paths (broker ↔ match, broker ↔ CA, CA ↔ policy)
- ✅ Auth command protocol with state management
- ✅ OIDC authentication with token refresh
- ✅ Certificate signing and SSH agent integration
- ✅ End-to-end flow for simple single-user scenarios

**What's needed for production**:
- ❌ Certificate matching that considers user/identity/principals
- ❌ Real policy server that validates tokens and makes authorization decisions
- ❌ Testing with multiple users and complex authorization scenarios
- ❌ Production examples and deployment guides beyond trivial cases

**Next Steps**:
1. Design and implement proper certificate matching (policy includes user dimensions)
2. Build a reference policy server implementation (validates OIDC tokens, checks claims, makes real authz decisions)
3. Validate multi-user scenarios
4. Production deployment examples with realistic policies

### Available Examples

The `examples/` directory contains deployment guides and reference implementations:

- **`examples/bash_auth_example.bash`**: Reference bash auth plugin demonstrating the stdin/stdout/fd3 protocol
- **`examples/epithet.config.example`**: Sample config file showing key-value format and repeatable flags
- **`examples/aws-lambda/`**: Complete AWS Lambda deployment with CloudFormation/Terraform templates
- **`examples/google-workspace/`**: OIDC setup guide for Google Workspace integration (referenced in code)
- **`examples/README.md`**: Overview of deployment options and architecture choices

These examples demonstrate real-world usage patterns and serve as templates for custom deployments.
