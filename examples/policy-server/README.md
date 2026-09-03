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

### 2. Create policy and inventory files

Copy the examples and edit:

```bash
cp policy.example.writ policy.writ
cp inventory.example.yaml inventory.yaml
editor policy.writ inventory.yaml
```

Update:
- `policy.writ`: the access rules (who reaches which account on which hosts)
- `inventory.yaml`: your team members (SCIM-shaped) and your hosts (names/patterns + labels)

Then validate the pair:

```bash
./epithet policy --check --policy-file policy.writ --inventory inventory.yaml
```

You also need a small config file (`policy.yaml`) for the server settings:

```yaml
policy:
  oidc:
    issuer: "https://accounts.google.com"
    client-id: "your-client-id"
  policy-file: ./policy.writ
  inventory:
    - ./inventory.yaml
  # Compatibility default. See "Destination-bound mode" below before changing.
  principal-mode: account-name
```

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

With the example policy and inventory, alice (group `Admins`) may reach
`root` on any inventoried host:

```bash
ssh root@prod-web-1.example.com
```

The first time:
1. Browser opens for OIDC authentication
2. You authenticate with your identity provider
3. Policy server validates your token and issues a certificate
4. SSH connection proceeds with the certificate

Subsequent connections within the refresh token lifetime (~hours) will be fast (~100-200ms).

## Files in this example

- **`policy.example.writ`**: Template writ policy (the access rules)
- **`inventory.example.yaml`**: Template static inventory (users and hosts)
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
sudo cp policy.yaml policy.writ inventory.yaml /etc/epithet/
sudo chmod 600 /etc/epithet/ca_key
sudo chmod 640 /etc/epithet/policy.yaml /etc/epithet/policy.writ /etc/epithet/inventory.yaml
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
The initial FreeBSD package is host-focused and does not install server rc.d
services; run the CA and policy processes under an explicitly configured
supervisor.

## Configuring target hosts

Install the Epithet binary on each target SSH server, then enroll it. The local
example uses plain HTTP, so it also needs the explicit global `--insecure`
opt-in:

```console
$ sudo epithet --insecure host enroll --ca-url http://ca-server:8080/
epithet-host-v1-...
```

Enrollment downloads the CA key, creates the stable host ID, installs and
validates a managed sshd fragment, and reloads sshd. It defaults to
destination-bound principals.

### Destination-bound inventory

Copy the host ID printed by enrollment into the exact host's static inventory
entry and select the same principal mode:

```yaml
hosts:
  - name: prod-web-1.example.com
    labels: {env: prod, role: web}
    principal-mode: epithet-principal-v1
    host-id: "epithet-host-v1-..."
```

Set `policy.principal-mode: epithet-principal-v1` to make this the deployment
default. Exact hosts that inherit that default still need a `host-id`.
Static ephemeral patterns must explicitly fall back to
`account-name`.

The helper is offline and derives the accepted principal from the local host
ID and `%u`; it does not contact the policy server. See the
[policy server guide](../../docs/policy-server.md#target-host-configuration)
for permissions, migration, and host-identity details.

For an `account-name` compatibility host, enroll with
`--principal-mode account-name` and configure the matching inventory override.
That mode accepts a certificate for an account on any host in the CA trust
domain with the same account name; use it only where that broader boundary is
intentional.

## See also

- [Policy server guide](../../docs/policy-server.md) - Configuration and authorization details
- [OIDC setup](../../docs/oidc-setup.md) - Provider configuration
- [epithet-aws](https://github.com/epithet-ssh/epithet-aws) - AWS Lambda deployment
