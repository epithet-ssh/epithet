# CA private key stored in Secrets Manager
resource "aws_secretsmanager_secret" "ca_key" {
  name        = "${local.name_prefix}-ca-key"
  description = "Epithet CA private key (${var.ca_key_algorithm})"

  tags = local.common_tags
}

# Initial CA key (empty - will be populated by setup script)
resource "aws_secretsmanager_secret_version" "ca_key" {
  secret_id = aws_secretsmanager_secret.ca_key.id

  secret_string = jsonencode({
    algorithm   = var.ca_key_algorithm
    private_key = ""
    public_key  = ""
    created_at  = ""
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}
