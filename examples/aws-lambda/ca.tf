# IAM role for CA Lambda
resource "aws_iam_role" "ca_lambda" {
  name = "${local.name_prefix}-ca-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

# Policy to allow CA Lambda to write logs
resource "aws_iam_role_policy_attachment" "ca_lambda_logs" {
  role       = aws_iam_role.ca_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Policy to allow CA Lambda to read the CA private key from Secrets Manager
resource "aws_iam_role_policy" "ca_lambda_secrets" {
  name = "${local.name_prefix}-ca-secrets"
  role = aws_iam_role.ca_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue"
      ]
      Resource = aws_secretsmanager_secret.ca_key.arn
    }]
  })
}

# S3 bucket for certificate archival
resource "aws_s3_bucket" "cert_archive" {
  bucket = "${local.name_prefix}-cert-archive"

  tags = merge(local.common_tags, {
    Purpose = "Certificate audit trail and analytics"
  })
}

# Enable versioning on cert archive bucket (compliance best practice)
resource "aws_s3_bucket_versioning" "cert_archive" {
  bucket = aws_s3_bucket.cert_archive.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption for cert archive
resource "aws_s3_bucket_server_side_encryption_configuration" "cert_archive" {
  bucket = aws_s3_bucket.cert_archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access to cert archive
resource "aws_s3_bucket_public_access_block" "cert_archive" {
  bucket = aws_s3_bucket.cert_archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle policy for cert archive (optional: delete old archives)
resource "aws_s3_bucket_lifecycle_configuration" "cert_archive" {
  bucket = aws_s3_bucket.cert_archive.id

  rule {
    id     = "archive-retention"
    status = var.cert_archive_retention_days > 0 ? "Enabled" : "Disabled"

    expiration {
      days = var.cert_archive_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Policy to allow CA Lambda to write to cert archive bucket
resource "aws_iam_role_policy" "ca_lambda_s3" {
  name = "${local.name_prefix}-ca-s3"
  role = aws_iam_role.ca_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ]
      Resource = "${aws_s3_bucket.cert_archive.arn}/*"
    }]
  })
}

# CloudWatch log group for CA Lambda
resource "aws_cloudwatch_log_group" "ca_lambda" {
  name              = "/aws/lambda/${local.name_prefix}-ca"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# CA Lambda function
resource "aws_lambda_function" "ca" {
  filename         = "bin/bootstrap-ca.zip"
  function_name    = "${local.name_prefix}-ca"
  role             = aws_iam_role.ca_lambda.arn
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  memory_size      = var.lambda_memory_mb
  timeout          = var.lambda_timeout_sec
  source_code_hash = filebase64sha256("bin/bootstrap-ca.zip")

  environment {
    variables = {
      CA_SECRET_ARN        = aws_secretsmanager_secret.ca_key.arn
      POLICY_URL           = "${aws_apigatewayv2_api.policy.api_endpoint}/validate"
      LOG_LEVEL            = "info"
      EPITHET_CMD          = "aws ca"
      CERT_ARCHIVE_BUCKET  = aws_s3_bucket.cert_archive.id
      CERT_ARCHIVE_PREFIX  = "certs"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.ca_lambda,
    aws_iam_role_policy_attachment.ca_lambda_logs,
    aws_iam_role_policy.ca_lambda_secrets,
    aws_iam_role_policy.ca_lambda_s3,
  ]

  tags = local.common_tags
}

# API Gateway for CA
resource "aws_apigatewayv2_api" "ca" {
  name          = "${local.name_prefix}-ca"
  protocol_type = "HTTP"
  description   = "Epithet CA server"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST"]
    allow_headers = ["content-type"]
  }

  tags = local.common_tags
}

# API Gateway integration with CA Lambda
resource "aws_apigatewayv2_integration" "ca" {
  api_id                 = aws_apigatewayv2_api.ca.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.ca.invoke_arn
  payload_format_version = "2.0"
}

# API Gateway route for CA certificate signing
resource "aws_apigatewayv2_route" "ca_sign" {
  api_id    = aws_apigatewayv2_api.ca.id
  route_key = "POST /"
  target    = "integrations/${aws_apigatewayv2_integration.ca.id}"
}

# API Gateway route for CA public key retrieval
resource "aws_apigatewayv2_route" "ca_pubkey" {
  api_id    = aws_apigatewayv2_api.ca.id
  route_key = "GET /"
  target    = "integrations/${aws_apigatewayv2_integration.ca.id}"
}

# API Gateway stage for CA
resource "aws_apigatewayv2_stage" "ca" {
  api_id      = aws_apigatewayv2_api.ca.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.ca_api.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = local.common_tags
}

# CloudWatch log group for CA API Gateway
resource "aws_cloudwatch_log_group" "ca_api" {
  name              = "/aws/apigateway/${local.name_prefix}-ca"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# Permission for API Gateway to invoke CA Lambda
resource "aws_lambda_permission" "ca_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ca.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.ca.execution_arn}/*/*"
}
