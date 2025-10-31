#!/bin/bash
set -euo pipefail

# Generate CA key and upload to AWS Secrets Manager
# This script reads the secret name from OpenTofu outputs

# Check for required tools
if ! command -v tofu &> /dev/null; then
    echo "Error: OpenTofu not found. Install with: brew install opentofu"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI not found. Install with: brew install awscli"
    exit 1
fi

if ! command -v ssh-keygen &> /dev/null; then
    echo "Error: ssh-keygen not found"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq not found. Install with: brew install jq"
    exit 1
fi

# Get the secret name from OpenTofu output
echo "Getting secret name from OpenTofu..."
SECRET_NAME=$(tofu output -raw ca_secret_name)
REGION=$(tofu output -raw region)

if [ -z "$SECRET_NAME" ]; then
    echo "Error: Could not get secret name from OpenTofu output"
    echo "Make sure you've run 'tofu apply' first"
    exit 1
fi

echo "Generating Ed25519 key pair..."
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Generate Ed25519 key
ssh-keygen -t ed25519 -f "$TEMP_DIR/ca_key" -N "" -C "epithet-ca" >/dev/null 2>&1

# Read private and public keys
PRIVATE_KEY=$(cat "$TEMP_DIR/ca_key")
PUBLIC_KEY=$(cat "$TEMP_DIR/ca_key.pub")

# Create JSON secret
SECRET_JSON=$(jq -n \
    --arg algorithm "ed25519" \
    --arg private_key "$PRIVATE_KEY" \
    --arg public_key "$PUBLIC_KEY" \
    --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        algorithm: $algorithm,
        private_key: $private_key,
        public_key: $public_key,
        created_at: $created_at
    }')

echo "Uploading to AWS Secrets Manager..."
aws secretsmanager put-secret-value \
    --region "$REGION" \
    --secret-id "$SECRET_NAME" \
    --secret-string "$SECRET_JSON" \
    >/dev/null

echo ""
echo "✓ CA key generated and uploaded successfully"
echo ""
echo "CA Public Key:"
echo "$PUBLIC_KEY"
echo ""
echo "You can retrieve the public key anytime with:"
echo "  aws secretsmanager get-secret-value --region $REGION --secret-id $SECRET_NAME --query SecretString --output text | jq -r .public_key"
