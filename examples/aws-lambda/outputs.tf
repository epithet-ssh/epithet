output "ca_url" {
  description = "CA server API endpoint URL"
  value       = "${aws_apigatewayv2_api.ca.api_endpoint}/"
}

output "policy_url" {
  description = "Policy server API endpoint URL (internal use)"
  value       = "${aws_apigatewayv2_api.policy.api_endpoint}/validate"
}

output "ca_secret_name" {
  description = "Name of the Secrets Manager secret containing the CA key"
  value       = aws_secretsmanager_secret.ca_key.name
}

output "ca_public_key_command" {
  description = "Command to retrieve the CA public key"
  value       = "aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.ca_key.name} --query SecretString --output text | jq -r .public_key"
}

output "region" {
  description = "AWS region where resources are deployed"
  value       = var.aws_region
}
