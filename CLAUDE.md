# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Testing
```bash
# Build the project
cargo build

# Build in release mode
cargo build --release

# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_key_generation

# Run async tests (common pattern in this codebase)
cargo test test_server_start
```

### Code Quality
```bash
# Check code without building
cargo check

# Run clippy for linting
cargo clippy

# Format code
cargo fmt

# Check formatting without applying
cargo fmt --check
```

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

### Current vs. Target Command Interface

**Target Interface (from README.md):**
```bash
epithet auth --host %h --port %p --user %r --socket %C
```

**Current Implementation:**
```bash
epithet auth --host HOST --user USER --socket SOCKET
```
*Note: Missing `--port` argument, and current implementation only prints directory paths*

### Command Structure

- **`epithet auth`**:
  - **Target**: Main authentication handler with 5-step certificate/agent workflow
  - **Current**: Placeholder that prints project directories
- **`epithet agent`**:
  - **Target**: Main agent process managing tree of per-connection ssh-agent instances
  - **Current**: Placeholder that prints "starting epithet agent"
- **`epithet proxy`**:
  - **Target**: ProxyCommand functionality for SSH connections
  - **Current**: Hardcoded TCP proxy to "m0003:22"

### Key Modules

#### `src/commands/`
- **auth.rs**: Currently prints directory paths; needs implementation of 5-step certificate workflow
- **agent.rs**: Currently minimal placeholder; needs to manage ssh-agent process tree
- **proxy.rs**: Basic TCP proxy (hardcoded to m0003:22); needs proper ProxyCommand implementation

#### `src/ssh.rs`
- SSH key generation utilities using Ed25519 algorithm
- Uses `ssh-key` crate for OpenSSH format compatibility
- Comprehensive tests for key generation and format validation

#### `src/testing/`
- **sshd.rs**: Mock SSH server for testing, binds to ephemeral ports
- Test infrastructure using `assertor` for assertions

### Technical Implementation Details

- **Key Algorithm**: Exclusively uses Ed25519 for SSH keys
- **Async Runtime**: Built on tokio for async networking and I/O
- **Configuration**: Uses `directories` crate for cross-platform config/data directories
- **Socket Management**: *Planned* - per-connection agent sockets using SSH connection hash (%C)
- **CLI Framework**: Uses clap with derive macros for command-line parsing
- **Agent Integration**: *Planned* - ssh-agent process management, possibly using ssh-agent-client-rs

### Integration with OpenSSH

Epithet is designed to integrate with OpenSSH client configuration:

```ssh_config
Match exec epithet auth --host %h --port %p --user %r --socket %C
    IdentityAgent ~/.epithet/sockets/%C
```

The `%C` token represents a hash of the connection parameters (local hostname, remote hostname, port, username, and ProxyJump), ensuring each unique connection gets its own agent socket.

### Current Development Status

This is v2 of the project with significant architectural changes planned (see README.md for detailed v2 vision). The current implementation is in a transitional state with placeholder code that will require substantial refactoring.

**What exists now:**
- Basic CLI structure and command routing with clap
- SSH key generation capabilities (Ed25519, well-tested)
- Test infrastructure using assertor and tokio
- Placeholder command implementations that don't match the target architecture

**Major development needed to align with README.md v2 plan:**

1. **`epithet auth` command redesign:**
   - Add missing `--port` argument to match planned interface
   - Implement 5-step certificate validation and agent creation workflow
   - Add host eligibility checking
   - Implement certificate lifecycle management with expiration handling

2. **Agent architecture implementation:**
   - Build connection → agent mapping system using %C hash
   - Integrate with ssh-agent processes (consider ssh-agent-client-rs crate)
   - Implement per-connection agent socket creation in ~/.epithet/sockets/%C
   - Add certificate swapping/renewal without changing socket paths

3. **Certificate management:**
   - Certificate authority integration
   - Certificate validation and expiration checking
   - Authentication flow for certificate requests
   - Destination constraining for security

4. **Infrastructure improvements:**
   - Configuration system for which hosts epithet should handle
   - Proper error handling throughout the certificate workflow
   - Socket cleanup on certificate expiration

The current code serves as a foundation but the core functionality described in README.md still needs to be implemented.