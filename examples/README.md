# Epithet Deployment Examples

This directory contains example deployments for epithet's CA and policy server components.

## Available Examples

### [aws-lambda/](aws-lambda/)

Deploy epithet CA and policy server to AWS Lambda with API Gateway using OpenTofu (open-source Terraform fork).

**Best for:**
- Personal/small team use
- Serverless operations (no infrastructure management)
- Cost-effective (~$1/month)
- Getting started quickly

**Architecture:**
- CA server on AWS Lambda (ARM64)
- Policy server on AWS Lambda (ARM64)
- API Gateway for HTTPS endpoints
- Secrets Manager for CA private key storage
- CloudWatch for logs

See [aws-lambda/README.md](aws-lambda/README.md) for deployment instructions.

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
