# Epithet makes SSH certificates easy

Epithet is an SSH certificate authority that replaces static authorized_keys with short-lived certificates (2-10 minutes) and authentication over OIDC. It creates on-demand SSH agents for each outbound connection, enabling real-time policy enforcement without touching your target hosts.

## Quick start

**1. Build epithet:**
```bash
git clone https://github.com/epithet-ssh/epithet.git
cd epithet
make
```

**2. Start the agent:**
```bash
epithet agent --ca-url https://your-ca.example.com/
```

The agent discovers its OIDC issuer and client ID from the CA's Link header
on the root response — nothing to configure locally.

**3. Tag the hosts this profile should handle, then include the generated config** (`~/.ssh/config`):

```ssh_config
Host *.example.com
    Tag epithet

Include ~/.epithet/run/*/ssh-config.conf   # must come after Tag lines
```

**4. SSH as normal:**
```bash
ssh server.example.com
```

First connection authenticates through your browser (~2-5 seconds). In an SSH
session, Epithet automatically uses the OIDC device flow instead. Subsequent
connections reuse the refreshed token.

To scope the agent to a shell or another command, pass that command to the
agent. It starts only after the broker is ready, and the agent exits when the
command exits:

```bash
epithet agent zsh
```

The child uses the same generated `~/.ssh/config` setup shown above. Use
`--login-method browser` or `--login-method device` to override automatic
login-method selection.

## How it works

When you run `ssh server.example.com`, OpenSSH's `Match tagged` triggers `epithet match` for hosts you've tagged in your own ssh config. `epithet match` asks the broker for a certificate. The broker authenticates in-process via OIDC, requests a signed certificate from the CA (which checks policy in real time), and spins up a per-connection SSH agent with the short-lived certificate. See [architecture](docs/architecture.md#sequence-diagrams) for detailed sequence diagrams.

**Components:**

- **Agent** (`epithet agent`): Daemon managing OIDC authentication state and certificate lifecycle. Creates per-connection SSH agents.
- **CA** (`epithet ca`): Authenticates users, reads facts, evaluates Writ locally, and signs SSH certificates.
- **Control** (`epithet control`): Handles administration, SCIM provisioning, and host enrollment using its own signing key.
- **Directory / Inventory** (`epithet directory`, `epithet inventory`): Independently replaceable user and host fact services. Backends own storage, mutation invariants, and audit.
- **Combined launcher** (`epithet server`): Supervises these four separate services and the public router. See [deployment](docs/inventory.md).

## Documentation

- [Architecture](docs/architecture.md) - How epithet works under the hood
- [SCIM Provisioning](docs/scim.md) - Pocket ID setup, directory lifecycle, and group bindings
- [Writ Policy Guide](docs/policy-server.md) - Authorization rules and configuration
- [Fact Provider API](docs/fact-services.md) - Implement a custom directory or inventory
- [Destination-bound Principals](docs/principals.md) - Interoperable principal derivation protocol
- [Authentication](docs/authentication.md) - The OIDC token contract and in-process auth flow
- [OIDC Setup](docs/oidc-setup.md) - Provider-specific OIDC configuration (Google, Okta, Azure AD)
- [Releasing](docs/RELEASING.md) - Notes on cutting releases

**Requires OpenSSH 9.4+** on the client (for `Tag`/`Match tagged`; see below).

## License

Apache 2.0
