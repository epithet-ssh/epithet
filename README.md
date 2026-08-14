# Epithet makes SSH certificates easy

[![Actions Status](https://github.com/epithet-ssh/epithet/workflows/build/badge.svg)](https://github.com/epithet-ssh/epithet/actions) [![Go Reportcard](https://goreportcard.com/badge/github.com/epithet-ssh/epithet)](https://goreportcard.com/report/github.com/epithet-ssh/epithet)

Epithet is an SSH certificate authority that replaces static authorized_keys with short-lived certificates (2-10 minutes). It creates on-demand SSH agents for each outbound connection, enabling real-time policy enforcement without touching your target hosts.

Authentication is OIDC only, handled in-process by the broker — no plugins, no subprocess auth commands.

**Requires OpenSSH 9.4+** on the client (for `Tag`/`Match tagged`; see below).

## Quick start

**1. Build epithet:**
```bash
git clone https://github.com/epithet-ssh/epithet.git
cd epithet
make build
```

**2. Start the agent:**
```bash
epithet agent --ca-url https://your-ca.example.com --name work
```

The agent fetches its OIDC issuer and client ID from the CA's `/discovery`
endpoint — nothing to configure locally.

**3. Tag the hosts this profile should handle, then include the generated config** (`~/.ssh/config`):
```ssh_config
Host *.example.com
    Tag epithet-work
Include ~/.epithet/run/*/ssh-config.conf   # must come after Tag lines
```

**4. SSH as normal:**
```bash
ssh server.example.com
```

First connection opens your browser for authentication (~2-5 seconds). Subsequent connections reuse the refreshed token (~100-200ms).

## How it works

When you run `ssh server.example.com`, OpenSSH's `Match tagged` triggers `epithet match` for hosts you've tagged in your own ssh config. `epithet match` asks the broker for a certificate. The broker authenticates in-process via OIDC, requests a signed certificate from the CA (which checks policy in real time), and spins up a per-connection SSH agent with the short-lived certificate. See [architecture](docs/architecture.md#sequence-diagrams) for detailed sequence diagrams.

**Components:**

- **Broker** (`epithet agent`): Daemon managing OIDC authentication state and certificate lifecycle. Creates per-connection SSH agents.
- **CA Server** (`epithet ca`): Signs SSH certificates after passing the caller's token through to a policy server for validation.
- **Policy Server** (`epithet policy`): Validates tokens and makes authorization decisions - who can access what hosts as which users.
- **Per-connection Agents**: In-process SSH agents, one per unique connection, serving a certificate minted for that connection alone.

## Commands

| Command | Description |
|---------|-------------|
| `epithet agent` | Start the broker daemon that manages certificates and agents |
| `epithet agent inspect` | Query a running broker's state |
| `epithet server` | Run the CA and policy server as supervised subprocesses behind one port |
| `epithet match` | Called by SSH `Match exec` to trigger certificate flow |
| `epithet ca` | Run the certificate authority server |
| `epithet policy` | Run the policy server with OIDC-based authorization |

## Documentation

- [Architecture](docs/architecture.md) - How epithet works under the hood
- [Policy Server Guide](docs/policy-server.md) - Setup and configuration for the policy server
- [Authentication](docs/authentication.md) - The OIDC token contract and in-process auth flow
- [OIDC Setup](docs/oidc-setup.md) - Provider-specific OIDC configuration (Google, Okta, Azure AD)
- [Releasing](docs/RELEASING.md) - Notes on cutting releases

## Development

```bash
make build    # Build all binaries
make test     # Run tests
make clean    # Clean build artifacts
```

Requirements: Go 1.25+

## License

Apache 2.0
