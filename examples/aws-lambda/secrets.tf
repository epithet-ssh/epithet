# CA private key stored in Secrets Manager
resource "aws_secretsmanager_secret" "ca_key" {
  name                    = "${local.name_prefix}-ca-key"
  description             = "Epithet CA private key (${var.ca_key_algorithm})"
  recovery_window_in_days = 0 # Force immediate deletion on destroy

  tags = local.common_tags
}

# Data source to read CA public key for policy server
# Note: The secret value is populated by running `make setup-ca-key`
data "aws_secretsmanager_secret_version" "ca_key" {
  secret_id = aws_secretsmanager_secret.ca_key.id
}

# Extract public key from the secret JSON
locals {
  ca_secret_data = jsondecode(data.aws_secretsmanager_secret_version.ca_key.secret_string)
  ca_public_key  = try(local.ca_secret_data.public_key, "")
}
