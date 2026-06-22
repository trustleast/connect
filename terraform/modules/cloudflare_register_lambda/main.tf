terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.4"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# ── SSM ────────────────────────────────────────────────────────────────────────

resource "aws_ssm_parameter" "cf_api_token" {
  name  = var.cf_api_token_ssm_path
  type  = "SecureString"
  value = var.cloudflare_api_token
}

# ── IAM ────────────────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_region" "current" {}

resource "aws_iam_role" "lambda" {
  name               = "connect-cf-registrar-${data.aws_region.current.region}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda_permissions" {
  statement {
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
  statement {
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.cf_api_token.arn]
  }
  statement {
    actions   = ["autoscaling:CompleteLifecycleAction"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_permissions" {
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# ── Lambda ─────────────────────────────────────────────────────────────────────

data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/registrar.zip"

  source_file = "${path.module}/handler.py"
}

resource "aws_lambda_function" "registrar" {
  function_name    = "signaling-cf-registrar"
  role             = aws_iam_role.lambda.arn
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 90

  environment {
    variables = {
      CF_ZONE_ID            = var.cloudflare_zone_id
      CF_ZONE_NAME          = join(".", slice(split(".", var.domain), 1, length(split(".", var.domain))))
      CF_DOMAIN             = var.domain
      CF_API_TOKEN_SSM_PATH = var.cf_api_token_ssm_path
    }
  }
}

# ── EventBridge ────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "launch" {
  name        = "signaling-asg-launch"
  description = "ASG launch lifecycle hook — ${var.asg_name}"
  event_pattern = jsonencode({
    source        = ["aws.autoscaling"]
    "detail-type" = ["EC2 Instance-launch Lifecycle Action"]
    detail        = { AutoScalingGroupName = [var.asg_name] }
  })
}

resource "aws_cloudwatch_event_rule" "terminate" {
  name        = "signaling-asg-terminate"
  description = "ASG terminate lifecycle hook — ${var.asg_name}"
  event_pattern = jsonencode({
    source        = ["aws.autoscaling"]
    "detail-type" = ["EC2 Instance-terminate Lifecycle Action"]
    detail        = { AutoScalingGroupName = [var.asg_name] }
  })
}

resource "aws_cloudwatch_event_target" "launch" {
  rule = aws_cloudwatch_event_rule.launch.name
  arn  = aws_lambda_function.registrar.arn
}

resource "aws_cloudwatch_event_target" "terminate" {
  rule = aws_cloudwatch_event_rule.terminate.name
  arn  = aws_lambda_function.registrar.arn
}

resource "aws_lambda_permission" "launch" {
  statement_id  = "AllowEventBridgeLaunch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.registrar.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.launch.arn
}

resource "aws_lambda_permission" "terminate" {
  statement_id  = "AllowEventBridgeTerminate"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.registrar.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.terminate.arn
}

# ── ASG lifecycle hooks ────────────────────────────────────────────────────────

resource "aws_autoscaling_lifecycle_hook" "launch" {
  name                   = "signaling-launch"
  autoscaling_group_name = var.asg_name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
  default_result         = "CONTINUE"
  heartbeat_timeout      = var.lifecycle_hook_timeout
}

resource "aws_autoscaling_lifecycle_hook" "terminate" {
  name                   = "signaling-terminate"
  autoscaling_group_name = var.asg_name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  default_result         = "CONTINUE"
  heartbeat_timeout      = var.lifecycle_hook_timeout
}

# ── Outputs ────────────────────────────────────────────────────────────────────

output "lambda_arn" {
  value       = aws_lambda_function.registrar.arn
  description = "Registrar Lambda ARN"
}
