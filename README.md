# Epithet makes SSH certificates easy

[![Actions Status](https://github.com/epithet-ssh/epithet/workflows/build/badge.svg)](https://github.com/epithet-ssh/epithet/actions) [![Go Reportcard](https://goreportcard.com/badge/github.com/epithet-ssh/epithet)](https://goreportcard.com/report/github.com/epithet-ssh/epithet)

Epithet is an SSH certificate authority that replaces static authorized_keys with short-lived certificates (2-10 minutes). It creates on-demand SSH agents for each outbound connection, enabling real-time policy enforcement without touching your target hosts.

## Quick start

**1. Build epithet:**
```bash
git clone https://github.com/epithet-ssh/epithet.git
cd epithet
make build
```

**2. Start the agent:**
```bash
epithet agent \
  --ca-url https://your-ca.example.com \
  --auth "epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID"
```

**3. Add to your SSH config** (`~/.ssh/config`):
```ssh_config
Include ~/.epithet/run/*/ssh-config.conf
```

**4. SSH as normal:**
```bash
ssh server.example.com
```

First connection opens your browser for authentication (~2-5 seconds). Subsequent connections use cached tokens (~100-200ms).

## How it works

When you run `ssh server.example.com`, OpenSSH's Match exec triggers `epithet match`, which asks the broker for a certificate. The broker handles authentication (via browser-based OIDC or a custom auth plugin), requests a signed certificate from the CA (which checks policy in real-time), and spins up a per-connection SSH agent with the short-lived certificate. See [architecture](docs/architecture.md#sequence-diagrams) for detailed sequence diagrams.

**Components:**

- **Broker** (`epithet agent`): Daemon managing authentication state and certificate lifecycle. Creates per-connection SSH agents.
- **CA Server** (`epithet ca`): Signs SSH certificates after validating tokens against a policy server.
- **Policy Server** (`epithet policy`): Makes authorization decisions - who can access what hosts as which users.
- **Per-connection Agents**: In-process SSH agents, one per unique connection, serving short-lived certificates.

## Commands

| Command | Description |
|---------|-------------|
| `epithet agent` | Start the broker daemon that manages certificates and agents |
| `epithet agent inspect` | Query a running broker's state |
| `epithet server` | Run the CA and policy server together |
| `epithet match` | Called by SSH Match exec to trigger certificate flow |
| `epithet ca` | Run the certificate authority server |
| `epithet policy` | Run the policy server with OIDC authorization |
| `epithet auth oidc` | Built-in OIDC/OAuth2 authentication plugin |

## Documentation

- [Architecture](docs/architecture.md) - How epithet works under the hood
- [Policy Server Guide](docs/policy-server.md) - Setup and configuration for the policy server
- [Authentication](docs/authentication.md) - Auth plugin protocol and custom plugins
- [OIDC Setup](docs/oidc-setup.md) - Provider-specific OIDC configuration (Google, Okta, Azure AD)

## Development

```bash
make build    # Build all binaries
make test     # Run tests
make clean    # Clean build artifacts
```

Requirements: Go 1.25+

## License

Apache 2.0
