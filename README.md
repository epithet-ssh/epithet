# Epithet makes SSH certificates easy

Epithet is an SSH certificate authority that replaces static authorized_keys with short-lived certificates (2-10 minutes) and authentication over OIDC. It creates on-demand SSH agents for each outbound connection, enabling real-time policy enforcement with standard OpenSSH.

## Community

Very small right now, but we have a [mailing list](https://groups.google.com/g/epithet-dev)!

## Installation

### macOS

Install with [Homebrew](https://brew.sh/) on Apple Silicon or Intel Macs:

```sh
brew install epithet-ssh/tap/epithet
```

### FreeBSD

Packages are available for FreeBSD 15 on amd64. Run the following as root to
install the repository signing key and configure the signed package repository:

```sh
install -d -m 0755 /usr/local/etc/pkg/keys /usr/local/etc/pkg/repos
fetch -o /usr/local/etc/pkg/keys/epithet.pub https://pkg.epithet.dev/keys/epithet.pub
chmod 0644 /usr/local/etc/pkg/keys/epithet.pub
cat > /usr/local/etc/pkg/repos/Epithet.conf <<'EOF'
Epithet: {
    url: "https://pkg.epithet.dev/${ABI}/latest",
    signature_type: "pubkey",
    pubkey: "/usr/local/etc/pkg/keys/epithet.pub",
    enabled: yes
}
EOF
pkg update -r Epithet
pkg install -r Epithet epithet
```

Keep the literal `${ABI}` in the repository URL. The package includes server
rc.d scripts, disabled by default; installation does not start a server.


### Debian Linux

Packages are available for amd64. Run the following as root to install the
repository and then epithet:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsS https://pkg.epithet.dev/keys/epithet-debian.asc \
  -o /etc/apt/keyrings/epithet-debian.asc
sudo chmod 0644 /etc/apt/keyrings/epithet-debian.asc

sudo tee /etc/apt/sources.list.d/epithet.sources >/dev/null <<'SOURCES'
Types: deb
URIs: https://pkg.epithet.dev/debian
Suites: ./
Architectures: amd64
Signed-By: /etc/apt/keyrings/epithet-debian.asc
SOURCES

sudo apt-get update && sudo apt-get install -y epithet
```

### Arch Linux

Packages are available for x86_64. Import and trust the repository signing key:

```sh
curl -fsS --proto '=https' https://pkg.epithet.dev/keys/epithet-arch.asc | sudo pacman-key --add -
sudo pacman-key --lsign-key EDF8AFF765FBCD24AE3E2D0B1146870201C33C51
```

Add the following to `/etc/pacman.conf`, keeping the literal `$arch`:

```ini
[epithet]
SigLevel = Required
Server = https://pkg.epithet.dev/arch/$arch
```

Then update the system and install Epithet:

```sh
sudo pacman -Syu epithet
```

### From source

```bash
git clone https://github.com/epithet-ssh/epithet.git
cd epithet
make
```

Add the resulting `epithet` binary to your `PATH`.

## Quick start

**1. [Install Epithet](#installation).**

**2. Start the agent:**
```bash
epithet agent --ca https://your-ca.example.com/
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
- **CA** (`epithet ca`): Authenticates users, reads facts, evaluates Writ, and signs SSH certificates.
- **Directory / Inventory** (`epithet directory`, `epithet inventory`): Independently replaceable user and host fact services. Backends own storage, mutation invariants, and audit.
- **Control** (`epithet control`): Control plan, handles administration, SCIM provisioning, and host enrollment.

## Documentation

- [Directory and SCIM groups](pkg/facts/directory/README.md) - identities, current group names, and database upgrades
- [Fact Provider API](docs/fact-services.md) - Implement a custom directory or inventory
- [Destination-bound Principals](docs/principals.md) - Interoperable principal derivation protocol

**Requires OpenSSH 9.4+** on the client (for `Tag`/`Match tagged`; see below).

## License

Apache 2.0
