# Development Tools

Epithet includes development tools under the `epithet dev` command to help with testing, debugging, and local development.

## Dev Policy Server

The `epithet dev policy` command runs a policy server for testing certificate workflows. This tool is useful for:

- Local development and testing of the CA
- Integration testing with SSH clients
- Debugging certificate issuance flows
- Testing different policy scenarios

### Basic Usage

```bash
# Start a development policy server that approves all requests
# Using CA URL (most common for development)
epithet dev policy -p root -p admin --ca-pubkey http://localhost:8080

# Using a file path
epithet dev policy -p root --ca-pubkey /path/to/ca.pub -v

# Using a literal SSH public key
epithet dev policy -p root --ca-pubkey "ssh-ed25519 AAAA..." -P 8080
```

### Policy Modes

The dev policy server supports two modes controlled by the `--mode` flag:

#### 1. Allow-All Mode (default)

Approves all certificate requests regardless of the connection details. Uses `HostPattern: "*"` which matches all hosts.

```bash
epithet dev policy -p root -p admin --ca-pubkey http://localhost:8080 --mode allow-all
```

**Use case:** Testing basic certificate issuance and SSH connections.

#### 2. Deny-All Mode

Denies all certificate requests with HTTP 403 Forbidden.

```bash
epithet dev policy -p root --ca-pubkey http://localhost:8080 --mode deny-all
```

**Use case:** Testing error handling and fallback behavior when policy denies access.

### Configuration Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--principals` | `-p` | (required) | SSH principals to assign (can be repeated) |
| `--ca-pubkey` | - | (required) | CA public key: URL (http://...), file path, or literal SSH key |
| `--port` | `-P` | 9999 | Port to listen on |
| `--mode` | `-m` | allow-all | Policy mode: allow-all, deny-all |
| `--identity` | `-i` | steve | Identity field in certificate |
| `--expiration` | `-e` | 1m | Certificate expiration duration (e.g., 1m, 5m, 1h) |
| `--verbose` | `-v` | - | Increase verbosity (repeat for more detail) |

### Examples

#### Testing with Short-Lived Certificates

```bash
# Certificates expire in 30 seconds - good for testing expiration handling
epithet dev policy -p root --ca-pubkey http://localhost:8080 --expiration 30s -v
```

#### Testing with Multiple Principals

```bash
# Assign multiple principals to test principal selection
epithet dev policy -p root -p admin -p deploy -p www-data --ca-pubkey http://localhost:8080
```

#### Testing Identity Fields

```bash
# Test with different identity values
epithet dev policy -p root --ca-pubkey http://localhost:8080 --identity "alice@example.com"
epithet dev policy -p root --ca-pubkey http://localhost:8080 --identity "service-account"
```

### Integration with CA

The typical workflow is to start the CA first, then point the policy server at the CA's URL to automatically fetch the public key:

```bash
# Start the CA first
epithet ca --policy http://localhost:9999 --key /path/to/ca.key &

# Start the dev policy server pointing to the CA URL
# It will automatically fetch the CA's public key via GET
epithet dev policy -p root --ca-pubkey http://localhost:8080 -P 9999 -v
```

Alternatively, you can use a file path or literal key:

```bash
# Using a file path
epithet dev policy -p root --ca-pubkey /path/to/ca.pub -P 9999 -v

# Using a literal SSH public key
epithet dev policy -p root --ca-pubkey "ssh-ed25519 AAAA..." -P 9999 -v
```

### Logging

The dev policy server logs all policy decisions:

```
INFO  starting dev policy server addr=:9999 mode=allow-all principals=[root] identity=steve expiration=1m0s
INFO  policy decision: approved (allow-all mode) remote_user=alice remote_host=server.example.com port=22
INFO  policy decision: denied (deny-all mode) remote_user=bob remote_host=other.com port=22
```

Use `-v` for info-level logging, `-vv` for debug-level logging.

### Security Warning

**DO NOT use the dev policy server in production!**

This tool is designed for development and testing only. It has minimal security controls and should never be exposed to production traffic or untrusted networks.

For production policy servers:
- Implement proper authentication token validation
- Use real authorization logic based on your organization's policies
- Add rate limiting and monitoring
- Use HTTPS/TLS
- Implement comprehensive logging and auditing
- Follow the [Policy Server API specification](policy-server-api.yaml)

### Advanced Testing Scenarios

#### Testing Certificate Expiration

```bash
# Very short expiration to test renewal flows
epithet dev policy -p root --ca-pubkey http://localhost:8080 --expiration 10s

# Watch certificates expire and renew
ssh -o "Match exec epithet match --host %h --port %p --user %r --hash %C" user@host
```

#### Testing Policy Changes

```bash
# Start with allow-all
epithet dev policy -p root --ca-pubkey http://localhost:8080 --mode allow-all

# Stop and restart with deny-all to test fallback
epithet dev policy -p root --ca-pubkey http://localhost:8080 --mode deny-all
```

#### Testing Multiple CA Instances

```bash
# Start two CAs on different ports
epithet ca --policy http://localhost:9999 --key test-ca.key &
epithet ca --policy http://localhost:9998 --key prod-ca.key --address :8081 &

# Start policy servers pointing to each CA
epithet dev policy -p root --ca-pubkey http://localhost:8080 -P 9999 &
epithet dev policy -p root --ca-pubkey http://localhost:8081 --mode deny-all -P 9998 &
```

## Future Dev Commands

The `epithet dev` namespace is reserved for development tools. Future additions may include:

- `epithet dev ca` - Run a development CA with default test keys
- `epithet dev auth` - Run a mock auth plugin for testing
- `epithet dev keygen` - Generate test CA keys and certificates
