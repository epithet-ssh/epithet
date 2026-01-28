# Architecture

Epithet is an SSH certificate management tool that creates on-demand SSH agents for outbound connections. The core concept is to replace traditional SSH key-based authentication with certificate-based authentication using per-connection agents.

**Implementation status**: The v2 architecture is **complete and production-ready**. All protocols, communication paths, and policy logic are fully implemented.

## Terminology

- **Broker**: The daemon process started by `epithet agent`. It manages user authentication state, certificate lifecycle, and creates per-connection agent instances. The broker is the central coordinator for all epithet functionality on an endpoint. Each broker instance creates a unique directory under `~/.epithet/run/<instance-hash>/` containing its socket, agent sockets, and auto-generated SSH config.
- **Per-connection agents**: Individual in-process SSH agent instances (from `pkg/agent`), one per unique SSH connection (identified by %C hash). Each serves a single certificate via an agent socket at `~/.epithet/run/<instance-hash>/agent/%C`. Uses `golang.org/x/crypto/ssh/agent` for efficient in-process agent implementation (much lower overhead than spawning OpenSSH ssh-agent processes).
- **Auth command**: External command configured by the user (via `--auth` flag) that handles authentication with identity providers (SAML, OIDC, etc). The broker invokes this command to obtain authentication tokens. Can be a custom script or use the built-in `epithet auth oidc` command for OAuth2/OIDC providers.

## v2 architecture

The `epithet match` workflow implements 5 key steps (fully functional in `pkg/broker/broker.go:Match()`):

1. **Host pattern matching**: Check if the host should be handled by epithet at all (abort early if not)
2. **Certificate lookup**: Check for existing, unexpired certificate for the target user/host (with 5-second expiry buffer)
3. **Agent with existing cert**: If certificate exists, ensure agent socket at %C exists with that certificate
4. **Certificate request**: If no certificate exists, request one (including authentication), then go to step 3
5. **Expiry cleanup**: Background cleanup deletes expired agent sockets every 30 seconds

**Certificate swapping**: The broker implements intelligent certificate reuse via `Agent.UseCredential()` - when a certificate expires, the broker can swap a fresh certificate into the existing agent without changing the socket path. This provides seamless renewal for long-running SSH sessions.

## Command structure

The `epithet` binary uses `alecthomas/kong` for command-line parsing, with CUE-based config file loading supporting YAML, CUE, and JSON formats with multi-file unification. All commands are fully implemented and production-ready.

### epithet match

```
epithet match --host %h --port %p --user %r --hash %C [--jump %j] [--broker <path>]
```

- **Status**: ✅ Fully implemented (`cmd/epithet/match.go`)
- Invoked by OpenSSH Match exec during connection establishment
- Implements 5-step certificate/agent workflow via RPC to broker
- Communicates with the broker (started by `epithet agent`) to request certificates
- Returns success/failure to OpenSSH to control whether connection proceeds
- Optional `--broker` flag specifies broker socket path (for multiple broker instances)

### epithet agent

```
epithet agent --ca-url <url> --auth <command> [--config <file>]
```

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

### epithet ca

```
epithet ca --policy <url> --key <path> --address <addr>
```

- **Status**: ✅ Fully implemented (`cmd/epithet/ca.go`, `pkg/ca/`, `pkg/caserver/`)
- Runs the CA server as a standalone HTTP service
- Listens on specified address (default 0.0.0.0:8080)
- Reads CA private key from file
- Validates certificate requests against policy server with cryptographic verification

### epithet auth oidc

```
epithet auth oidc --issuer <url> --client-id <id> [--client-secret <secret>]
```

- **Status**: ✅ Fully implemented (`cmd/epithet/auth_oidc.go`)
- Built-in OIDC/OAuth2 authentication plugin
- Implements the auth command protocol (stdin/stdout/fd3)
- Supports PKCE for public clients (no client secret needed)
- Handles token refresh automatically via refresh tokens
- Works with Google Workspace, Okta, Azure AD, and other OIDC providers
- Uses browser-based authentication flow with local callback server
- See `examples/google-workspace/` for setup guide

## Core components

The system consists of four main components (all fully implemented):

1. **CA Server** (`pkg/ca`, `pkg/caserver`, `cmd/epithet-ca`): The certificate authority that signs SSH certificates. Accepts tokens via `Authorization: Bearer` header. Uses shape-based routing: empty body for hello requests (token validation only), or full body with publicKey+connection for certificate requests. Validates tokens against a policy server using cryptographic verification (SSH signature via Rekor/Sigstore over the request body), then signs public keys to create certificates. Returns certificates with policy metadata (hostPattern) for intelligent reuse.

2. **CA Client** (`pkg/caclient`): HTTP client library that requests certificates from the CA server. Sends tokens in the `Authorization: Bearer` header. Provides `GetCert()` for certificate requests and `Hello()` for token validation without requesting a certificate. Includes domain-specific error types for different failure modes (InvalidTokenError, PolicyDeniedError, ConnectionNotHandledError, CAUnavailableError). Supports multi-CA failover with circuit breakers.

3. **Broker** (`pkg/broker`): The daemon process managing certificate lifecycle and authentication on endpoints. Orchestrates auth commands (stdin/stdout/fd3 protocol), CA requests with retry logic, and per-connection agent instances. Uses net/rpc over Unix domain socket for communication with `epithet match`. Implements policy-based certificate reuse and automatic expiry cleanup.

4. **Per-connection Agents** (`pkg/agent`): In-process SSH agent implementation using `golang.org/x/crypto/ssh/agent`. One agent instance per unique connection, each exposing a Unix socket at `~/.epithet/run/<instance-hash>/agent/%C`. Provides low-overhead SSH agent protocol implementation without spawning external processes. Supports atomic certificate swapping via `UseCredential()`.

## Authentication mechanism

The broker uses an external **auth command** to obtain authentication tokens. This design allows epithet to work with any identity provider (SAML, OIDC, Kerberos, custom) without the broker needing to understand authentication protocols.

**Implementation status**: ✅ Fully implemented in `pkg/broker/auth.go` with comprehensive test coverage (18 tests). The built-in `epithet auth oidc` command (`cmd/epithet/auth_oidc.go`) provides production-ready OAuth2/OIDC support.

### Auth command protocol

The broker communicates with auth plugins using a file descriptor protocol: stdin receives previous state, stdout returns the token, fd 3 returns new state, stderr receives errors. State is opaque to the broker (max 10 MiB) and never touches disk.

See [authentication.md](authentication.md) for full protocol details, examples in Bash/Python/Go, and the `examples/bash_auth_example.bash` reference implementation.

### Certificate lifecycle with short-lived certificates

**Key timing decision**: SSH certificates are **short-lived (2-10 minutes)** to enable real-time policy enforcement.

**Authentication vs certificate expiry:**
- **Auth sessions**: Long-lived (hours/days) via refresh tokens stored in state blob
- **SSH certificates**: Short-lived (2-10 minutes) for just-in-time authorization
- **Auth command calls**: Only when certificate expires (not proactively)

**Rationale for short certificate lifetime:**
- Minimal blast radius if certificate is stolen/compromised
- CA policy server evaluates "can this user access this host RIGHT NOW" for small values of now
- Time-bound access reduces risk in dynamic environments
- Stolen credentials have very limited window of usefulness

**User experience:**
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

## Key data flow

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

## Important types and abstractions

- **`sshcert.RawPrivateKey`, `RawPublicKey`, `RawCertificate`**: Type-safe wrappers for SSH keys/certs in on-disk format (string-based)
- **`ca.CertParams`**: Policy response containing identity, principals, expiration, and extensions for a certificate
- **`policy.Connection`**: Connection details (%h, %p, %r, %C, %j) passed through Match → Broker → CA → Policy
- **`policy.Policy`**: Policy metadata (hostPattern) returned with certificates for intelligent reuse
- **`agent.Credential`**: Private key + certificate pair used by the agent
- **`caclient.InvalidTokenError`, `PolicyDeniedError`, `ConnectionNotHandledError`, `CAUnavailableError`**: Domain-specific error types for CA failures

## Protocols

### Broker → CA protocol

The broker requests certificates from the CA over HTTP with tokens in `Authorization: Bearer` header. Shape-based routing: both `publicKey` + `connection` for cert requests, empty body for hello/validation requests.

**Error codes**: 401 (re-auth needed), 403 (policy denied), 422 (connection not handled), 5xx (CA unavailable, triggers failover).

### CA → Policy server protocol

The CA validates tokens by calling the policy server over HTTP. The CA signs the request body using its SSH private key (Sigstore SSH signing); the policy server verifies this signature to ensure requests come from the legitimate CA.

See [policy-server.md](policy-server.md) for the full HTTP API specification, request/response formats, and error handling details.

## Error handling and match behavior

These design decisions affect how epithet interacts with SSH's Match exec behavior.

### SSH config precedence

- SSH uses **first match wins** for configuration parameters
- More specific Match blocks should appear before general ones
- When a Match exec returns non-zero, that Match block doesn't apply and SSH continues to the next Match or default config

### Match failure strategy

When epithet cannot obtain a certificate (auth failures, CA errors, agent creation failures):
1. **Log clear error to stderr** - User-friendly message explaining what went wrong (verbosity matching configured log level)
2. **Exit with non-zero status** - Fail the Match so SSH falls through to next config
3. **Allow SSH fallback** - Enables breakglass/escape hatch scenarios

**Rationale:**
- Enables breakglass accounts: users can have epithet Match blocks first, then special-case configs (e.g., `Match host *.example.com user breakglass` with specific IdentityFile)
- If epithet fails the Match, SSH can try other auth methods (default keys, other agents)
- Trade-off: May leak connection attempts to fallback systems, but this is acceptable to enable legitimate escape hatches
- Users who need strict security can configure SSH with no fallbacks after epithet Match blocks

**Multiple concurrent brokers**: Epithet supports multiple broker instances (work vs personal, different CAs). Each needs a unique socket path via `--broker`. See `examples/` for configuration patterns.

### CA error handling

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

### Auth plugin error handling

**Exit 0 with error field** - User-facing auth failure (cancelled flow, MFA failed, invalid credentials):
1. Keep the existing state (don't clear it)
2. Fail the Match with the error message from auth plugin
3. User can retry SSH connection when ready

**Non-zero exit** - Unexpected error (network issue, plugin crash, etc):
1. Keep the existing state
2. Retry up to limit (same as CA 401 retry limit)
3. If retries exhausted, fail the Match with error
4. Use immediate retries (no backoff)

### Certificate and agent management

**Certificate storage:**
- Always store certificates obtained from CA, even if agent creation later fails
- Certificates are bound to policies (hostPattern), not individual agents
- Multiple agents (different connection hashes) may reuse the same certificate if policy matches
- Keep certificates in store even on agent creation failures (cert is still valid)

**Agent creation failures:**
- Typically local system issues (permissions, disk space, socket directory problems)
- Keep certificate in store (it's valid, may work on retry)
- Fail the Match with clear error explaining the local issue (not a cert/auth problem)
- User can fix local issue and retry

## Configuration and SSH integration

When `epithet agent` starts, it auto-generates an SSH config at `~/.epithet/run/<instance-hash>/ssh-config.conf`. Include it via `Include ~/.epithet/run/*/ssh-config.conf` in your `~/.ssh/config`.

Config files use YAML, CUE, or JSON in `~/.epithet/`. Multi-file unification via CUE merges all config files; conflicting values cause startup errors. Use `snake_case` in configs (maps to `--kebab-case` flags). See `examples/epithet.config.example` for a complete example.

## Project structure

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

## Testing infrastructure

**Status**: ✅ Comprehensive test coverage across all components

The project includes:
- **Unit tests**: 12 test files covering all major packages (agent, broker, auth, CA, certs, caclient, caserver, sshcert, oidc)
- **Integration tests**: `test/sshd/broker_test.go` provides full end-to-end testing with real sshd server, validating the complete flow: broker → auth → CA → policy → certificate → agent → SSH connection
- **Test infrastructure**: `test/sshd/` package provides utilities for running real SSH servers in tests
- **Mock auth scripts**: Example bash scripts for testing broker flows without real identity providers
- **Mock policy server**: Test implementations for validating CA flows

Run all tests with `make test` or `go test ./...`.
