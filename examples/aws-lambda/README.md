# AWS Lambda Deployment Example

This example shows how to deploy epithet's CA and policy server to AWS Lambda behind API Gateway using OpenTofu (open-source Terraform alternative), and configure both client and server for SSH certificate authentication.

## Prerequisites

- [OpenTofu](https://opentofu.org/) installed (`brew install opentofu` on macOS)
- AWS CLI configured with credentials
- Go 1.25+ for building Lambda binaries
- SSH access to target servers you want to configure

## Architecture

```
epithet client → API Gateway → Lambda (CA) → API Gateway → Lambda (Policy)
                                    ↓
                              Secrets Manager (CA private key)
```

- **CA Lambda**: Handles certificate signing requests
- **Policy Lambda**: Validates tokens and evaluates access policies
- **API Gateway**: Exposes HTTPS endpoints for both services
- **Secrets Manager**: Stores the CA's Ed25519 private key

## Configuration

All configuration is done via environment variables:

```bash
# Required
export TF_VAR_aws_region="us-west-2"              # AWS region to deploy to
export TF_VAR_project_name="epithet-personal"     # Project name (used in resource names)

# Optional
export TF_VAR_ca_key_algorithm="ed25519"          # CA key algorithm (ed25519 or rsa)
export TF_VAR_ca_key_bits="256"                   # Key size (256 for ed25519, 4096 for rsa)
export TF_VAR_lambda_memory_mb="256"              # Lambda memory allocation
export TF_VAR_lambda_timeout_sec="30"             # Lambda timeout
```

## Quick Start

### Part 1: Deploy the CA to AWS Lambda

1. **Set required environment variables:**

```bash
export TF_VAR_aws_region="us-west-2"
export TF_VAR_project_name="epithet-personal"
```

2. **Build and deploy:**

```bash
cd examples/aws-lambda
make build
make init
make apply
```

3. **Generate and upload the CA private key:**

```bash
make setup-ca-key
```

4. **Save the CA URL for later:**

```bash
tofu output -raw ca_url
# Example output: https://abc123xyz.execute-api.us-west-2.amazonaws.com/
```

### Part 2: Configure SSH Servers

On each SSH server you want to accept epithet certificates:

1. **Get the CA public key:**

```bash
# On your local machine
cd examples/aws-lambda
curl $(tofu output -raw ca_url)pubkey > /tmp/epithet-ca.pub

# Copy to server
scp /tmp/epithet-ca.pub yourserver:/tmp/
```

2. **Configure the SSH server to trust the CA:**

```bash
# SSH into the server
ssh yourserver

# Install the CA public key
sudo mkdir -p /etc/ssh/ca
sudo mv /tmp/epithet-ca.pub /etc/ssh/ca/epithet-ca.pub

# Configure sshd to trust this CA
echo "TrustedUserCAKeys /etc/ssh/ca/epithet-ca.pub" | sudo tee -a /etc/ssh/sshd_config
echo "AuthorizedPrincipalsFile /etc/ssh/principals/%u" | sudo tee -a /etc/ssh/sshd_config

# Restart sshd
sudo systemctl restart sshd  # On systemd-based systems
# OR
sudo service sshd restart    # On other systems
```

3. **Configure authorized principals for each user:**

The default policy server issues certificates with the `testuser` principal. You need to authorize this principal for each user:

```bash
# Create principals directory
sudo mkdir -p /etc/ssh/principals

# Allow "testuser" principal to authenticate as "yourusername"
echo "testuser" | sudo tee /etc/ssh/principals/yourusername
```

**Note:** For production use, you should customize the policy server to issue different principals based on your authentication system.

### Part 3: Configure Your Local Machine

1. **Create a simple test auth plugin:**

```bash
mkdir -p ~/.epithet
cat > ~/.epithet/test-auth-plugin << 'EOF'
#!/bin/bash
# Simple test auth plugin - returns a static token
# In production, this would do real authentication (OAuth, OIDC, etc.)

# Read state from stdin (ignore for this test)
cat > /dev/null

# Output a test token to stdout
echo -n "test-token-123"

# Output empty state to fd 3
echo -n "" >&3
EOF

chmod +x ~/.epithet/test-auth-plugin
```

2. **Build and install epithet locally:**

```bash
# From the project root
make build
sudo cp epithet /usr/local/bin/
```

3. **Create epithet config file (optional but recommended):**

```bash
# Get the CA URL from your deployment
cd examples/aws-lambda
CA_URL=$(tofu output -raw ca_url)

# Create config file using template expansion
cat > ~/.epithet/config << EOF
# Match patterns for hosts epithet should handle
match yourserver

# CA URL
ca-url $CA_URL

# Auth plugin (using config_dir template for relative path)
auth {config_dir}/test-auth-plugin
EOF
```

**Config file template syntax:**
- `{config_dir}` - directory containing the config file (`~/.epithet`)
- `{home}` - user's home directory
- `{env.VAR_NAME}` - environment variable expansion

4. **Start the epithet broker:**

```bash
# Using config file (recommended):
epithet agent

# Or using command-line flags:
epithet agent \
  --match 'yourserver' \
  --ca-url $(tofu output -raw ca_url) \
  --auth ~/.epithet/test-auth-plugin
```

The broker will automatically:
- Create a unique temporary directory in `~/.epithet/run/<instance-id>/`
- Generate SSH config file, broker socket, and agent sockets in that directory
- Check if your `~/.ssh/config` has the required Include directive (warns if missing)
- Clean up everything when it stops

5. **Configure SSH to use epithet:**

Add this single line to the top of your `~/.ssh/config`:

```ssh_config
Include ~/.epithet/run/*/ssh-config.conf

# Your existing SSH config below...
Host yourserver
    User yourusername
```

The wildcard include picks up all broker config files automatically. Multiple brokers (e.g., work and personal) can run simultaneously, each in its own directory with no conflicts.

**Note:** If you forget to add the Include line, the broker will warn you at startup with the exact line you need to add.

6. **Test the connection:**

```bash
# Unset SSH_AUTH_SOCK if you have one set
unset SSH_AUTH_SOCK  # In bash/zsh
# OR
set -e SSH_AUTH_SOCK  # In fish

# Connect!
ssh yourserver
```

If everything is configured correctly, you should be authenticated using the certificate from epithet!

## Troubleshooting

### SSH still asks for a password or tries my RSA key

This usually means:
1. The SSH config isn't being applied (check with `ssh -vv yourserver` to see what config it's using)
2. The `epithet match` command failed (check broker logs)
3. You have `SSH_AUTH_SOCK` set in your environment (unset it)

### "Certificate does not contain an authorized principal"

This means the server doesn't recognize the principal in the certificate. Check:
1. The principals file exists: `cat /etc/ssh/principals/yourusername`
2. The principals file contains `testuser`
3. The sshd_config has `AuthorizedPrincipalsFile /etc/ssh/principals/%u`

### Certificate is rejected by the server

Check the server's auth logs:
```bash
# On the SSH server
sudo journalctl -u sshd -f  # On systemd systems
# OR
sudo tail -f /var/log/auth.log  # On other systems
```

Look for messages about certificate validation failures.

### Broker can't connect to CA

Check:
1. The CA URL is correct: `tofu output ca_url`
2. You can reach the CA: `curl $(tofu output -raw ca_url)pubkey`
3. The broker logs for specific errors

## Implementation Details

### CA Lambda
The CA Lambda uses the main `epithet` binary with the `aws ca` subcommand. The `EPITHET_CMD` environment variable tells the binary to run in Lambda mode as `aws ca`.

### Policy Lambda
The policy Lambda is implemented in Python (`lambda/policy/main.py`) for easy customization.

The example includes a simple **allow-all policy** for personal use. This is **NOT suitable for production** or multi-user environments!

To customize the policy, edit `lambda/policy/main.py`. Several example policies are included:

- **Host-based access**: Restrict access based on hostname patterns
- **Time-based access**: Allow access only during business hours
- **External authorization**: Integrate with DynamoDB, external APIs, etc.

See `lambda/policy/README.md` for detailed customization instructions and examples.

**Why Python?** Python makes it easy to customize policy logic without recompiling. You can edit the policy, re-zip, and redeploy in seconds.

## Cleanup

To destroy all resources:

```bash
tofu destroy
```

## Cost Estimate

With typical personal use (a few connections per day):
- API Gateway: ~$0.05/month
- Lambda: ~$0.10/month (mostly free tier)
- Secrets Manager: ~$0.40/month
- **Total: <$1/month**

## Customization

- **CA key rotation**: Generate a new key and update the secret in Secrets Manager
- **Policy logic**: Edit `lambda/policy/main.go` and redeploy
- **Multiple environments**: Use different `project_name` values for dev/prod
- **Custom domains**: Add API Gateway custom domain resources to `main.tf`
