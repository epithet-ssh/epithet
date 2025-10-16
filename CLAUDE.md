# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Epithet is an SSH certificate authority system that makes SSH certificates easy to use. The project is currently undergoing a v2 rewrite (see README.md for v2 architecture details).

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
- Go: Use `github.com/markdingo/netstring` library (note: requires manual whitespace handling between netstrings)

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
Match exec "epithet auth --host %h --port %p --user %r --hash %C"
    IdentityAgent ~/.epithet/sockets/%C
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
