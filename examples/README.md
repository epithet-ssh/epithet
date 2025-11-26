# Epithet Deployment Examples

This directory contains example deployments and reference implementations for epithet.

## Available Examples

- **`bash_auth_example.bash`**: Reference bash auth plugin demonstrating the stdin/stdout/fd3 protocol
- **`epithet.config.example`**: Sample config file showing key-value format and repeatable flags
- **`google-workspace/`**: OIDC setup guide for Google Workspace integration
- **`policy-server/`**: Policy server configuration examples
- **`client/`**: Client configuration examples
- **`example-target-host/`**: SSH server configuration for trusting epithet certificates

## AWS Lambda Deployment

For deploying epithet CA and policy server on AWS Lambda, see the dedicated repository:

**[epithet-aws](https://github.com/epithet-ssh/epithet-aws)** - AWS Lambda deployment template

Features:
- CA and policy server on AWS Lambda (ARM64)
- API Gateway for HTTPS endpoints
- Secrets Manager for CA private key storage
- S3 certificate archival
- OpenTofu/Terraform infrastructure
- Cost-effective (~$1/month)

## Future Examples

Additional deployment examples planned:
- **GCP Cloud Functions**: Similar serverless approach on Google Cloud Platform
- **Kubernetes**: Container-based deployment with secrets management
- **Docker Compose**: Simple local or VM-based deployment
- **Systemd**: Traditional Linux service deployment

## Contributing Examples

If you create a deployment configuration for another platform, please contribute it back! Examples should:
- Be self-contained in their own directory
- Include clear README with prerequisites and instructions
- Use infrastructure-as-code tools where possible
- Document cost estimates and operational considerations
