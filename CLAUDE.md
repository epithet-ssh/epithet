# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Epithet is an SSH certificate authority system that makes SSH certificates easy to use. The project is currently undergoing a v2 rewrite (see README.md for v2 architecture details).

## High-Level Architecture

**IMPORTANT**: The current codebase contains placeholder implementations that do not yet match the v2 plan described in README.md. Future development will align the code with this architectural vision.

Epithet is an SSH certificate management tool that creates on-demand SSH agents for outbound connections. The core concept is to replace traditional SSH key-based authentication with certificate-based authentication using per-connection agents.

### Target v2 Architecture (from README.md)

The planned `epithet auth` workflow involves 5 key steps:
1. Check if the host should be handled by epithet at all (abort early if not)
2. Check for existing, unexpired certificate for the target user/host
3. If certificate exists, set up an identity socket at %C with only that certificate
4. If no certificate exists, request one (including authentication), then go to step 3
5. When certificate expires, delete the socket at %C

Step 5 may be refined - rather than deleting on expiration, certificates near expiration (1-2 seconds) could be renewed and swapped into the existing agent without changing the socket path.

### Command Structure (Planned)

**Current Implementation**: The `epithet` binary currently uses `peterbourgon/ff/v3` with `ffcli` for command-line parsing, config file support, and environment variable handling.

**PLANNED PORT TO KONG**: After investigation, the decision has been made to port from ff/v3 to `alecthomas/kong` for CLI parsing. Kong provides better ergonomics, more powerful flag parsing, and cleaner command structure. This port should be done before implementing the actual agent and auth functionality.

- **`epithet auth --host %h --port %p --user %r --hash %C`**:
  - Main authentication handler invoked by OpenSSH Match exec
  - Implements 5-step certificate/agent workflow
  - Communicates with `epithet agent` to manage per-connection agents

- **`epithet agent`**:
  - Main agent process managing tree of per-connection ssh-agent instances
  - Maintains map of connection hash → agent process
  - Spawns OpenSSH ssh-agent processes for each unique connection
  - Tracks certificate expiration and public keys
  - Configuration via `--match` (repeatable) and `--ca-url` flags
  - Supports config file and environment variables (EPITHET_MATCH, EPITHET_CA_URL)

### Core Architecture

The system consists of three main components:

1. **CA Server** (`pkg/ca`, `pkg/caserver`, `cmd/epithet-ca`): The certificate authority that signs SSH certificates. It validates tokens against a policy server, then signs public keys to create certificates.

2. **CA Client** (`pkg/caclient`): HTTP client library that requests certificates from the CA server by submitting tokens and public keys.

3. **Agent** (`pkg/agent`): SSH agent that manages certificates on endpoints. Creates on-demand agent sockets for outbound connections, handles certificate lifecycle, and automatically renews expiring certificates.

### Key Data Flow

1. Agent generates an ephemeral keypair
2. Agent requests certificate from CA server with a token
3. CA server validates token against policy server (external HTTP endpoint)
4. CA server returns signed certificate with principals, expiration, and extensions
5. Agent serves certificate via SSH agent protocol on a per-connection socket

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
- Working CA server (`epithet-ca`) with policy validation
- Simplified SSH agent (`pkg/agent`) with certificate management
- SSH certificate utilities (`pkg/sshcert`) for Ed25519 key generation
- CA client library for requesting certificates
- Test infrastructure with real sshd integration tests
- `epithet` CLI with scaffolded `agent` and `auth` subcommands (currently using ff/v3, to be ported to kong)

**Major development needed to align with README.md v2 plan:**

0. **Port CLI from ff/v3 to kong:**
   - Replace ff/v3/ffcli with alecthomas/kong for command parsing
   - Maintain existing flag structure (--match, --ca-url for agent; --host, --port, --user, --hash for auth)
   - Preserve config file support and environment variable handling
   - Keep long-form flag style (--flag not -flag) in all documentation

1. **`epithet auth` command implementation:**
   - Create command structure accepting `--host`, `--port`, `--user`, `--hash` arguments
   - Implement 5-step certificate validation and agent creation workflow
   - Add host eligibility checking
   - Implement certificate lifecycle management with expiration handling

2. **`epithet-agent` command implementation:**
   - Build connection → agent mapping system using %C hash
   - Spawn per-connection ssh-agent processes (OpenSSH's ssh-agent)
   - Implement per-connection agent socket creation in ~/.epithet/sockets/%C
   - Add certificate swapping/renewal without changing socket paths
   - Track certificate expiration and public keys for each agent

3. **Agent coordination:**
   - Communication between `epithet auth` and `epithet-agent` (likely using protobuf/gRPC)
   - Socket management and cleanup
   - Destination constraining for security

4. **Infrastructure improvements:**
   - Configuration system for which hosts epithet should handle
   - Proper error handling throughout the certificate workflow
   - Socket cleanup on certificate expiration

The current `pkg/agent` code is simplified and ready to be adapted for the v2 per-connection agent architecture.
