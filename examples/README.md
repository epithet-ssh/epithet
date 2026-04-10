# Epithet deployment examples

This directory contains example deployments and reference implementations for epithet.

## Available examples

- **`bash_auth_example.bash`**: Reference bash auth plugin demonstrating the stdin/stdout/fd3 protocol
- **`epithet.config.example`**: Sample config file in YAML format (also supports JSON)
- **`google-workspace/`**: OIDC setup guide for Google Workspace integration
- **`policy-server/`**: Policy server configuration examples
- **`client/`**: Client configuration examples
- **`example-target-host/`**: SSH server configuration for trusting epithet certificates

## AWS Lambda deployment

For deploying epithet CA and policy server on AWS Lambda, see the dedicated repository:

**[epithet-aws](https://github.com/epithet-ssh/epithet-aws)** - AWS Lambda deployment template

Features:
- CA and policy server on AWS Lambda (ARM64)
- API Gateway for HTTPS endpoints
- Secrets Manager for CA private key storage
- S3 certificate archival
- OpenTofu/Terraform infrastructure
- Cost-effective (~$1/month)

