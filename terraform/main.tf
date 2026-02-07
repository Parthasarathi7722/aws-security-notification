
# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Lambda Execution Role
resource "aws_iam_role" "lambda_execution_role" {
  name               = var.lambda_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

# Lambda Execution Policy
resource "aws_iam_role_policy" "lambda_execution_policy" {
  name = "${var.lambda_role_name}-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.notification_queue.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "s3:GetBucketPolicy",
          "s3:GetBucketLocation",
          "cloudtrail:LookupEvents",
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ],
    var.enable_guardduty ? [{
      Effect   = "Allow"
      Action   = ["guardduty:GetFindings", "guardduty:ListDetectors", "guardduty:ListFindings"]
      Resource = "*"
    }] : [],
    var.enable_security_hub ? [{
      Effect   = "Allow"
      Action   = ["securityhub:GetFindings", "securityhub:BatchImportFindings"]
      Resource = "*"
    }] : [],
    var.enable_config ? [{
      Effect   = "Allow"
      Action   = ["config:GetComplianceDetailsByConfigRule", "config:DescribeConfigRules"]
      Resource = "*"
    }] : [],
    var.enable_ecs ? [{
      Effect   = "Allow"
      Action   = ["ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition"]
      Resource = "*"
    }] : [],
    var.enable_eks ? [{
      Effect   = "Allow"
      Action   = ["eks:ListClusters", "eks:DescribeCluster"]
      Resource = "*"
    }] : [])
  })
}

# SQS Queue
resource "aws_sqs_queue" "notification_queue" {
  name                       = "${var.function_name}-queue"
  visibility_timeout_seconds = var.lambda_timeout
  message_retention_seconds  = 1209600  # 14 days
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.notification_dlq.arn
    maxReceiveCount     = 3
  })

  tags = var.tags
}

# Dead Letter Queue
resource "aws_sqs_queue" "notification_dlq" {
  name                       = "${var.function_name}-dlq"
  message_retention_seconds  = 1209600  # 14 days

  tags = var.tags
}

# Lambda Function
resource "aws_lambda_function" "security_notification" {
  filename         = var.deployment_package_path
  function_name    = var.function_name
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "security_notifier.handler.lambda_handler"
  source_code_hash = filebase64sha256(var.deployment_package_path)
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.lambda_memory_size

  reserved_concurrent_executions = 5

  dead_letter_config {
    target_arn = aws_sqs_queue.notification_dlq.arn
  }

  environment {
    variables = merge({
      SLACK_WEBHOOK_URL        = var.slack_webhook_url
      ACCOUNT_NAME             = var.account_name
      WHITELIST_RESOURCES      = join(",", var.whitelist_resources)
      CRITICAL_EVENTS          = join(",", var.critical_events)
      ENABLE_GUARDDUTY         = var.enable_guardduty ? "true" : "false"
      ENABLE_SECURITYHUB       = var.enable_security_hub ? "true" : "false"
      ENABLE_CONFIG            = var.enable_config ? "true" : "false"
      ENABLE_ECS               = var.enable_ecs ? "true" : "false"
      ENABLE_EKS               = var.enable_eks ? "true" : "false"
      LOG_LEVEL                = var.log_level
      MAX_RETRIES              = tostring(var.max_retries)
      RETRY_DELAY_SECONDS      = tostring(var.retry_delay_seconds)
      RATE_LIMIT_PER_MINUTE    = tostring(var.rate_limit_per_minute)
      MAX_SLACK_MESSAGE_LENGTH = tostring(var.max_message_length)
    }, var.additional_environment_variables)
  }

  tags = var.tags
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# Lambda Event Source Mapping (SQS)
resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn = aws_sqs_queue.notification_queue.arn
  function_name    = aws_lambda_function.security_notification.arn
  batch_size       = 10
  enabled          = true
}

# EventBridge Rule for Security Events
resource "aws_cloudwatch_event_rule" "security_events" {
  name        = "${var.function_name}-security-events"
  description = "Capture security-related AWS events"

  event_pattern = jsonencode({
    source = [
      "aws.iam",
      "aws.s3",
      "aws.ec2",
      "aws.cloudtrail",
      "aws.config",
      "aws.guardduty",
      "aws.securityhub",
      "aws.kms",
      "aws.secretsmanager",
      "aws.ecs",
      "aws.eks"
    ]
    detail-type = [
      "AWS API Call via CloudTrail",
      "AWS Console Sign In via CloudTrail",
      "AWS Service Event"
    ]
    detail = {
      eventName = var.monitored_events
    }
  })

  tags = var.tags
}

# EventBridge Target (SQS)
resource "aws_cloudwatch_event_target" "sqs_target" {
  rule      = aws_cloudwatch_event_rule.security_events.name
  target_id = "SendToSQS"
  arn       = aws_sqs_queue.notification_queue.arn
}

# SQS Queue Policy for EventBridge
resource "aws_sqs_queue_policy" "notification_queue_policy" {
  queue_url = aws_sqs_queue.notification_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.notification_queue.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.security_events.arn
        }
      }
    }]
  })
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count               = var.enable_alarms ? 1 : 0
  alarm_name          = "${var.function_name}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors Lambda function errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.security_notification.function_name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  count               = var.enable_alarms ? 1 : 0
  alarm_name          = "${var.function_name}-dlq-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "60"
  statistic           = "Average"
  threshold           = "0"
  alarm_description   = "This metric monitors dead letter queue messages"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.notification_dlq.name
  }

  tags = var.tags
}

