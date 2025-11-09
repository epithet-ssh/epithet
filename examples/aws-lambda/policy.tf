# IAM role for Policy Lambda
resource "aws_iam_role" "policy_lambda" {
  name = "${local.name_prefix}-policy-lambda"

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

# Policy to allow Policy Lambda to write logs
resource "aws_iam_role_policy_attachment" "policy_lambda_logs" {
  role       = aws_iam_role.policy_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# CloudWatch log group for Policy Lambda
resource "aws_cloudwatch_log_group" "policy_lambda" {
  name              = "/aws/lambda/${local.name_prefix}-policy"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# Policy Lambda function
resource "aws_lambda_function" "policy" {
  filename         = "bin/bootstrap-policy.zip"
  function_name    = "${local.name_prefix}-policy"
  role             = aws_iam_role.policy_lambda.arn
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  memory_size      = var.lambda_memory_mb
  timeout          = var.lambda_timeout_sec
  source_code_hash = filebase64sha256("bin/bootstrap-policy.zip")

  environment {
    variables = {
      LOG_LEVEL     = "info"
      CA_PUBLIC_KEY = trimspace(local.ca_public_key)
      POLICY_SECRET = var.policy_secret
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.policy_lambda,
    aws_iam_role_policy_attachment.policy_lambda_logs,
  ]

  tags = local.common_tags
}

# API Gateway for Policy
resource "aws_apigatewayv2_api" "policy" {
  name          = "${local.name_prefix}-policy"
  protocol_type = "HTTP"
  description   = "Epithet policy server"

  tags = local.common_tags
}

# API Gateway integration with Policy Lambda
resource "aws_apigatewayv2_integration" "policy" {
  api_id                 = aws_apigatewayv2_api.policy.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.policy.invoke_arn
  payload_format_version = "2.0"
}

# API Gateway route for Policy
resource "aws_apigatewayv2_route" "policy_validate" {
  api_id    = aws_apigatewayv2_api.policy.id
  route_key = "POST /validate"
  target    = "integrations/${aws_apigatewayv2_integration.policy.id}"
}

# API Gateway stage for Policy
resource "aws_apigatewayv2_stage" "policy" {
  api_id      = aws_apigatewayv2_api.policy.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.policy_api.arn
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

# CloudWatch log group for Policy API Gateway
resource "aws_cloudwatch_log_group" "policy_api" {
  name              = "/aws/apigateway/${local.name_prefix}-policy"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# Permission for API Gateway to invoke Policy Lambda
resource "aws_lambda_permission" "policy_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.policy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.policy.execution_arn}/*/*"
}
