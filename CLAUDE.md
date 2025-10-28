# CLAUDE.md

**Note**: This project uses [bd (beads)](https://github.com/steveyegge/beads) for issue tracking. Use `bd` commands instead of markdown TODOs. See AGENTS.md for workflow details.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Epithet is an SSH certificate authority system that makes SSH certificates easy to use. The project is currently undergoing a v2 rewrite (see README.md for v2 architecture details).

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

**IMPORTANT**: The current codebase contains placeholder implementations that do not yet match the v2 plan described in README.md. Future development will align the code with this architectural vision.

Epithet is an SSH certificate management tool that creates on-demand SSH agents for outbound connections. The core concept is to replace traditional SSH key-based authentication with certificate-based authentication using per-connection agents.

### Terminology

- **Broker**: The daemon process started by `epithet agent`. It manages user authentication state, certificate lifecycle, and creates per-connection agent instances. The broker is the central coordinator for all epithet functionality on an endpoint.
- **Per-connection agents**: Individual in-process SSH agent instances (from `pkg/agent`), one per unique SSH connection (identified by %C hash). Each serves a single certificate via an agent socket at `~/.epithet/sockets/%C`. Uses `golang.org/x/crypto/ssh/agent` for efficient in-process agent implementation (much lower overhead than spawning OpenSSH ssh-agent processes).
- **Auth command**: External command configured by the user (via `--auth` flag) that handles authentication with identity providers (SAML, OIDC, etc). The broker invokes this command to obtain authentication tokens.

### Target v2 Architecture (from README.md)

The planned `epithet auth` workflow involves 5 key steps:
1. Check if the host should be handled by epithet at all (abort early if not)
2. Check for existing, unexpired certificate for the target user/host
3. If certificate exists, set up an identity socket at %C with only that certificate
4. If no certificate exists, request one (including authentication), then go to step 3
5. When certificate expires, delete the socket at %C

Step 5 may be refined - rather than deleting on expiration, certificates near expiration (1-2 seconds) could be renewed and swapped into the existing agent without changing the socket path.

### Command Structure

**Current Implementation**: The `epithet` binary uses `alecthomas/kong` for command-line parsing, with a custom KVLoader for config file support.

- **`epithet match --host %h --port %p --user %r --hash %C`**:
  - Invoked by OpenSSH Match exec during connection establishment
  - Implements 5-step certificate/agent workflow
  - Communicates with the broker (started by `epithet agent`) to request certificates
  - Returns success/failure to OpenSSH to control whether connection proceeds

- **`epithet agent --match <pattern> --ca-url <url> --auth <command>`**:
  - Starts the broker daemon
  - Required flags (can be set in config file):
    - `--match`: Repeatable patterns defining which hosts epithet should handle
    - `--ca-url`: URL of the certificate authority
    - `--auth`: Command to invoke for user authentication
  - The broker maintains:
    - Map of connection hash → per-connection agent instance (`pkg/agent.Agent`)
    - Map of user identity → authentication state
    - Certificate lifecycle and expiration tracking
  - Creates in-process SSH agent instances for each unique connection (low memory overhead)
  - Manages authentication state and token refresh

### Core Architecture

The system consists of four main components:

1. **CA Server** (`pkg/ca`, `pkg/caserver`, `cmd/epithet-ca`): The certificate authority that signs SSH certificates. It validates tokens against a policy server, then signs public keys to create certificates.

2. **CA Client** (`pkg/caclient`): HTTP client library that requests certificates from the CA server by submitting tokens and public keys.

3. **Broker** (`pkg/broker`): The daemon process managing certificate lifecycle and authentication on endpoints. Orchestrates auth commands, CA requests, and per-connection agent instances.

4. **Per-connection Agents** (`pkg/agent`): In-process SSH agent implementation using `golang.org/x/crypto/ssh/agent`. One agent instance per unique connection, each exposing a Unix socket at `~/.epithet/sockets/%C`. Provides low-overhead SSH agent protocol implementation without spawning external processes.

### Authentication Mechanism

The broker uses an external **auth command** to obtain authentication tokens. This design allows epithet to work with any identity provider (SAML, OIDC, Kerberos, custom) without the broker needing to understand authentication protocols.

#### Auth Command Protocol

The broker communicates with auth plugins using **keyed netstrings** (Type-Length-Value encoding). This protocol is language-agnostic, handles binary data without encoding overhead, and is self-describing.

**Netstring Format:** `<length>:<key><value>,`
- `<length>`: Decimal ASCII digits (no leading zeros except `0:,`)
- `<key>`: Single ASCII byte identifying field type
- `<value>`: Arbitrary bytes (length-1 bytes, since key takes 1 byte)
- Whitespace (spaces, tabs, `\n`, `\r`) between netstrings is **ignored** for debugging convenience

**Defined Keys:**
- `s` = State blob (opaque, managed by auth plugin)
- `t` = Authentication token (to be sent to CA)
- `e` = Error message (human-readable auth failure reason)

**Protocol Flow:**

**INPUT (stdin):**
```
# Initial authentication (no prior state)
0:,

# Token refresh (with existing state)
85:s{"refresh_token":"abc123","expires_at":"2025-10-14T15:00:00Z"},
```

**OUTPUT (stdout) - Success:**
```
218:teyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...,
92:s{"refresh_token":"xyz789","expires_at":"2025-10-14T16:00:00Z"},
```

**OUTPUT (stdout) - Failure:**
```
58:eRefresh token expired, full re-authentication required,
```

**Exit codes:**
- `0` with `t` key: Authentication successful
- `0` with `e` key: Authentication failed (user-facing error message)
- Non-zero exit: Unexpected error (stderr contains technical details)

**Design Properties:**
- Tokens and state are **completely opaque** to the broker (arbitrary byte blobs)
- Auth command owns session management (refresh tokens, token expiry, etc)
- Broker stores state and passes it to next invocation
- Self-describing format allows future protocol extensions without breaking existing plugins
- Whitespace tolerance allows use of `println()` for debugging

**Helper Libraries:**
- Bash: `examples/bash_plugin_helper.bash` provides `read_netstring()` and `write_netstring()` functions
- Go: Use `github.com/epithet-ssh/epithet/pkg/netstr` library (supports whitespace skipping via `netstr.SkipASCIIWhitespace()` option)

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
   - Broker calls: `echo "<state>" | auth-command`
   - Auth command uses refresh token to get fresh access token (~100ms)
   - Auth command returns: new token + updated state
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
- **`agent.Credential`**: Private key + certificate pair used by the agent

The CA uses cryptographic signing (via Rekor/Sigstore SSH signing) to authenticate requests to the policy server.

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

The project includes test support infrastructure in `test/sshd/` for running integration tests with actual SSH servers. Tests create real SSH connections to validate certificate functionality.

## Project Structure Notes

- Currently on branch `v2.go` working on v2 implementation
- Main branch for PRs is `master`
- Several files in `pkg/agent/hook/` have been deleted as part of v2 refactor
- The Makefile defines all standard development workflows
- Uses Go 1.25.0 with modules
- Dependencies include SSH libraries (`golang.org/x/crypto/ssh`), gRPC, protobuf, and Sigstore/Rekor for signing

## Important Constants

- `caserver.RequestBodySizeLimit = 8192`: Maximum HTTP request body size

### Integration with OpenSSH

Epithet is designed to integrate with OpenSSH client configuration:

```ssh_config
Match exec "epithet match --host %h --port %p --user %r --hash %C"
    IdentityAgent ~/.epithet/agent/%C
```

The `%C` token represents a hash of the connection parameters (`%l%h%p%r%j`: local hostname, remote hostname, port, username, and ProxyJump), ensuring each unique connection gets its own agent socket.

### Current Development Status

This is v2 of the project with significant architectural changes planned (see README.md for detailed v2 vision). The current implementation is in a transitional state - the agent has been simplified and cleaned up as a base for v2 work.

**What exists now:**
- ✅ Working CA server (`epithet-ca`) with policy validation
- ✅ In-process SSH agent implementation (`pkg/agent`) with certificate management
- ✅ SSH certificate utilities (`pkg/sshcert`) for Ed25519 key generation
- ✅ CA client library for requesting certificates
- ✅ Test infrastructure with real sshd integration tests
- ✅ `epithet` CLI using Kong for argument parsing
- ✅ KVLoader for config file support (key-value format with repeated flag support)
- ✅ Broker stub (`pkg/broker`) - basic structure in place

**Major development remaining for v2:**

1. **Broker authentication mechanism** (NEXT):
   - Implement auth command invocation (stdin/stdout protocol)
   - Auth state storage (map of user identity → state blob)
   - Certificate storage (map of connection hash → certificate + expiry)
   - Token refresh on certificate expiry
   - Error handling and retry logic

2. **`epithet match` command implementation:**
   - Create command structure accepting `--host`, `--port`, `--user`, `--hash` arguments
   - Communication protocol with broker (IPC/RPC)
   - Implement 5-step certificate validation workflow
   - Add host eligibility checking (match patterns)
   - Return success/failure to OpenSSH

3. **Broker → CA integration:**
   - Certificate request flow: auth token → CA → signed certificate
   - Pass connection details (host, user, port) to CA for principal determination
   - Handle CA errors and policy denials
   - Store returned certificates with expiry times

4. **Broker → Agent management:**
   - Create per-connection agent instances using `pkg/agent.Agent`
   - Map connection hash (%C) → agent instance
   - Agent socket path management at ~/.epithet/sockets/%C
   - Certificate swapping/renewal in existing agents (via `UseCredential`)
   - Agent lifecycle and cleanup

5. **Infrastructure improvements:**
   - Match pattern evaluation (which hosts epithet should handle)
   - Proper error handling throughout
   - Logging and observability
   - Socket cleanup on expiration
   - Graceful shutdown and state persistence
