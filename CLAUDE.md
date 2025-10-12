# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Epithet is an SSH certificate authority system that makes SSH certificates easy to use. The project is currently undergoing a v2 rewrite (see README.md for v2 architecture details).

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
make build          # Build all binaries (epithet-agent, epithet-ca, epithet-auth)
make epithet-ca     # Build only the CA server
make epithet-agent  # Build only the agent
make epithet-auth   # Build only the auth helper
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

## Configuration and Deployment

The `epithet-ca` server can be configured via flags or environment variables:
- `-p/--policy`: Policy server URL (or `POLICY_URL` env var)
- `-k/--key`: Path to CA private key (default: `/etc/epithet/ca.key`)
- `-a/--address`: Bind address (default: `0.0.0.0:${PORT:-8080}`)
- `-v`: Verbosity level (can be repeated)

## Important Constants

- `agent.CertExpirationFuzzWindow = 20`: Seconds before expiration to request new cert
- `agent.TokenSizeLimit = 4094`: Maximum authentication token size
- `caserver.RequestBodySizeLimit = 8192`: Maximum HTTP request body size
- `agent.DefaultTimeout = 30s`: Default HTTP timeout for CA requests
