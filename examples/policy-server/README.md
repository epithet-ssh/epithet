# Policy server example deployment

This example shows how to deploy epithet with the built-in OIDC-based policy server for a small team.

## Quick start

### 1. Generate CA key

```bash
ssh-keygen -t ed25519 -f ca_key -N "" -C "epithet-ca"
```

This creates:
- `ca_key` - Private key (keep secret!)
- `ca_key.pub` - Public key (distribute to target hosts)

### 2. Create policy configuration

Copy `policy.example.yaml` to `policy.yaml` and edit:

```bash
cp policy.example.yaml policy.yaml
editor policy.yaml
```

Update:
- `ca-pubkey`: Paste contents of `ca_key.pub`
- `oidc`: Your OIDC provider URL
- `users`: Add your team members

### 3. Start the services

```bash
# Terminal 1: Start CA server
./epithet ca \
  --key ./ca_key \
  --policy http://localhost:9999 \
  --listen :8080

# Terminal 2: Start policy server
./epithet policy \
  --config policy.yaml \
  --ca-pubkey "$(cat ca_key.pub)" \
  --listen 0.0.0.0:9999
```

### 4. Configure epithet agent

Create `~/.epithet/config.yaml`. OIDC issuer/client-id are discovered from the
CA's Link header at startup — the client needs no auth config of its own:

```yaml
agent:
  ca-url: http://localhost:8080
  name: default
```

Start the agent:

```bash
epithet agent
```

### 5. Add SSH configuration

Tag the hosts this profile should handle, then include epithet's
auto-generated config *after* those Tag lines (requires **OpenSSH 9.4+**
for `Tag`/`Match tagged`):

```
Host *.example.com
    Tag epithet
Include ~/.epithet/run/*/ssh-config.conf
```

### 6. Test SSH connection

```bash
ssh alice@server.example.com
```

The first time:
1. Browser opens for OIDC authentication
2. You authenticate with your identity provider
3. Policy server validates your token and issues a certificate
4. SSH connection proceeds with the certificate

Subsequent connections within the refresh token lifetime (~hours) will be fast (~100-200ms).

## Files in this example

- **`policy.example.yaml`**: Template policy configuration
- **`README.md`**: This file

See the [policy server guide](../../docs/policy-server.md) for detailed configuration and authorization documentation.

## Production deployment

`epithet` is a single static binary that runs in the foreground and logs to
stderr, so it drops into whatever supervisor you already use — systemd,
runit, rc.d, a container runtime. Install the binary and its config, then
supervise it:

```bash
# Install the binary
sudo cp epithet /usr/local/bin/

# Install configuration
sudo mkdir -p /etc/epithet
sudo cp ca_key /etc/epithet/
sudo cp policy.yaml /etc/epithet/
sudo chmod 600 /etc/epithet/ca_key
sudo chmod 640 /etc/epithet/policy.yaml
```

Two processes need supervising, and the CA depends on the policy server:

```bash
epithet policy --config /etc/epithet/policy.yaml
epithet ca --key /etc/epithet/ca_key --policy http://localhost:9999 --listen :8080
```

Put `ca-pubkey` in the policy config file rather than passing it as a flag —
most supervisors run `ExecStart`-style command lines without a shell, so a
`$(cat ca_key.pub)` substitution would be passed through literally.

For a single-process alternative that supervises both itself, see `epithet
server` in the [architecture guide](../../docs/architecture.md#epithet-server).
FreeBSD users have a packaged rc.d service in [`contrib/freebsd`](../../contrib/freebsd/).

## Configuring target hosts

On each target SSH server:

### 1. Install CA public key

```bash
sudo mkdir -p /etc/ssh/ca
sudo curl -o /etc/ssh/ca/epithet.pub http://ca-server:8080/
```

### 2. Configure sshd

Edit `/etc/ssh/sshd_config`:

```
# Trust epithet CA for user certificates
TrustedUserCAKeys /etc/ssh/ca/epithet.pub

# Optional: Require certificate authentication
PubkeyAuthentication yes
AuthenticationMethods publickey
```

Restart sshd:

```bash
sudo systemctl restart sshd
```

### 3. (Optional) add AuthorizedPrincipalsCommand

For additional host-side validation:

```bash
# Create a script that validates principals
sudo tee /usr/local/bin/check-principals.sh > /dev/null << 'EOF'
#!/bin/bash
# Check if the principal matches the local username
if [ "$1" = "$(whoami)" ]; then
  echo "$1"
fi
EOF

sudo chmod +x /usr/local/bin/check-principals.sh
```

Add to `/etc/ssh/sshd_config`:

```
AuthorizedPrincipalsCommand /usr/local/bin/check-principals.sh %u
AuthorizedPrincipalsCommandUser nobody
```

## See also

- [Policy server guide](../../docs/policy-server.md) - Configuration and authorization details
- [OIDC setup](../../docs/oidc-setup.md) - Provider configuration
- [epithet-aws](https://github.com/epithet-ssh/epithet-aws) - AWS Lambda deployment
