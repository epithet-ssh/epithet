# Policy Server Example Deployment

This example shows how to deploy epithet with the built-in OIDC-based policy server for a small team.

## Quick Start

### 1. Generate CA Key

```bash
ssh-keygen -t ed25519 -f ca_key -N "" -C "epithet-ca"
```

This creates:
- `ca_key` - Private key (keep secret!)
- `ca_key.pub` - Public key (distribute to target hosts)

### 2. Create Policy Configuration

Copy `policy.example.yaml` to `policy.yaml` and edit:

```bash
cp policy.example.yaml policy.yaml
editor policy.yaml
```

Update:
- `ca_public_key`: Paste contents of `ca_key.pub`
- `oidc`: Your OIDC provider URL
- `users`: Add your team members

### 3. Start the Services

```bash
# Terminal 1: Start CA server
./epithet ca \
  --key ./ca_key \
  --policy http://localhost:9999 \
  --address :8080

# Terminal 2: Start policy server
./epithet policy \
  --config-file policy.yaml \
  --ca-pubkey "$(cat ca_key.pub)" \
  --port 9999
```

### 4. Configure Epithet Agent

Create `~/.config/epithet/agent.conf`:

```
match *.example.com
ca-url http://localhost:8080
auth epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID
```

Start the agent:

```bash
epithet agent --config ~/.config/epithet/agent.conf
```

### 5. Add SSH Configuration

Add to `~/.ssh/config`:

```
Include ~/.epithet/run/*/ssh-config.conf
```

### 6. Test SSH Connection

```bash
ssh alice@server.example.com
```

The first time:
1. Browser opens for OIDC authentication
2. You authenticate with your identity provider
3. Policy server validates your token and issues a certificate
4. SSH connection proceeds with the certificate

Subsequent connections within the refresh token lifetime (~hours) will be fast (~100-200ms).

## Files in This Example

- **`policy.example.yaml`**: Template policy configuration
- **`systemd/`**: systemd service units for production deployment
- **`docker/`**: Docker Compose setup for containerized deployment
- **`README.md`**: This file

## Policy Configuration

The `policy.example.yaml` shows a typical small team setup:

- **Users**: 3 team members with different roles
- **Global defaults**: Standard SSH access for developers
- **Host-specific policies**: Restricted access to production databases

### Authorization Model

Users are assigned **tags** (like roles), and principals (SSH usernames) specify which tags are allowed:

```yaml
users:
  alice@example.com: [admin, dev]   # Alice has both admin and dev tags
  bob@example.com: [dev]             # Bob only has dev tag

defaults:
  allow:
    root: [admin]      # Only users with 'admin' tag can log in as root
    ubuntu: [dev]      # Users with 'dev' tag can log in as ubuntu
```

**Authorization logic:**
- User needs **at least one** matching tag to be authorized
- Alice can log in as both `root` (has `admin`) and `ubuntu` (has `dev`)
- Bob can only log in as `ubuntu` (has `dev`, not `admin`)

## Production Deployment

### Option 1: systemd Services

See `systemd/` directory for service unit files.

```bash
# Install binaries
sudo cp epithet /usr/local/bin/

# Install configuration
sudo mkdir -p /etc/epithet
sudo cp ca_key /etc/epithet/
sudo cp policy.yaml /etc/epithet/
sudo chmod 600 /etc/epithet/ca_key
sudo chmod 640 /etc/epithet/policy.yaml

# Install and start services
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable epithet-ca epithet-policy
sudo systemctl start epithet-ca epithet-policy

# Check status
sudo systemctl status epithet-ca epithet-policy
```

### Option 2: Docker Compose

See `docker/` directory for containerized deployment.

```bash
cd docker
docker-compose up -d

# Check logs
docker-compose logs -f
```

## Configuring Target Hosts

On each target SSH server:

### 1. Install CA Public Key

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

### 3. (Optional) Add AuthorizedPrincipalsCommand

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

## Monitoring and Logs

### CA Server Logs

```bash
# systemd
sudo journalctl -u epithet-ca -f

# Docker
docker-compose logs -f ca
```

### Policy Server Logs

```bash
# systemd
sudo journalctl -u epithet-policy -f

# Docker
docker-compose logs -f policy
```

### What to Monitor

- **Token validation failures**: May indicate OIDC provider issues
- **Authorization denials**: Users trying to access resources they don't have permissions for
- **CA signature verification failures**: May indicate configuration mismatch
- **High request rates**: May need to scale policy server

## Troubleshooting

### Users Can't Authenticate

1. **Check OIDC token validation:**
   ```bash
   # Look for "Invalid token" in policy server logs
   sudo journalctl -u epithet-policy | grep "Invalid token"
   ```

2. **Check user is in configuration:**
   ```bash
   # Verify user email matches exactly
   grep "alice@example.com" /etc/epithet/policy.yaml
   ```

3. **Check CA/policy communication:**
   ```bash
   # Verify CA can reach policy server
   curl -X POST http://localhost:9999/ \
     -H "Content-Type: application/json" \
     -d '{"token":"test","signature":"test","connection":{}}'
   ```

### SSH Connection Fails

1. **Check certificate was issued:**
   ```bash
   # Look for successful cert requests in CA logs
   sudo journalctl -u epithet-ca | grep "Signed certificate"
   ```

2. **Check target host trusts CA:**
   ```bash
   # On target host
   cat /etc/ssh/ca/epithet.pub
   grep TrustedUserCAKeys /etc/ssh/sshd_config
   ```

3. **Verify agent has certificate:**
   ```bash
   # Check agent socket
   ls -la ~/.epithet/run/*/agent/*
   ssh-add -L  # Should show certificate
   ```

## Security Best Practices

1. **Protect the CA private key**
   - Store with restrictive permissions (600)
   - Consider using a hardware security module (HSM) for production
   - Rotate periodically

2. **Keep certificates short-lived**
   - Default 5 minutes is recommended
   - Shorter for production systems (2 minutes)
   - Longer for development (10-30 minutes)

3. **Use TLS for production**
   - Put CA and policy server behind reverse proxy with TLS
   - Use Let's Encrypt or organizational certificates
   - Example with nginx in `nginx/` directory

4. **Monitor access**
   - Log all certificate issuance
   - Alert on suspicious patterns
   - Regular access review

5. **Implement least privilege**
   - Give users only the tags they need
   - Use host-specific policies for sensitive systems
   - Separate production and development policies

## Scaling

### For Larger Teams (10-50 users)

- Run multiple policy server instances behind a load balancer
- Consider separating CA and policy server to different hosts
- Use configuration management (Ansible, Puppet) to deploy CA public key to target hosts

### For Large Organizations (50+ users)

- Build a custom policy server that integrates with your directory service (LDAP, Active Directory)
- Use dynamic authorization (check group membership in real-time)
- Consider running CA as AWS Lambda (see `examples/aws-lambda/`)
- Implement certificate revocation checking

## Next Steps

- Read the [Policy Server Guide](../../docs/policy-server.md) for detailed configuration options
- See [Google Workspace Setup](../google-workspace/README.md) for OIDC provider setup
- Explore [AWS Lambda deployment](../aws-lambda/README.md) for serverless CA
