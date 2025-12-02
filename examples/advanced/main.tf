terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "security_notifications" {
  source = "../../terraform"

  slack_webhook_url = var.slack_webhook_url

  # Enable all optional services
  enable_guardduty    = true
  enable_security_hub = true
  enable_config       = true
  enable_ecs          = true
  enable_eks          = true

  # Custom configuration
  function_name      = "AdvancedSecurityMonitoring"
  account_name       = "Production Account"
  lambda_timeout     = 90
  lambda_memory_size = 512
  log_retention_days = 30

  # Security filtering
  whitelist_resources = [
    "arn:aws:iam::*:role/ServiceRole*",
    "arn:aws:iam::*:role/AWSServiceRole*"
  ]

  critical_events = [
    "CreateUser",
    "DeleteUser",
    "CreateRole",
    "DeleteRole",
    "PutBucketPolicy",
    "DeleteBucket"
  ]

  # Notification settings
  max_retries             = 3
  rate_limit_per_minute   = 30
  max_message_length      = 3000

  # Monitoring
  enable_alarms = true
  log_level     = "INFO"

  # Production tags
  tags = {
    Environment = "Production"
    Team        = "SecurityOps"
    Compliance  = "SOC2"
    CostCenter  = "Security"
    ManagedBy   = "Terraform"
    Project     = "SecurityMonitoring"
  }
}

variable "slack_webhook_url" {
  description = "Slack webhook URL"
  type        = string
  sensitive   = true
}

# Outputs
output "all_outputs" {
  description = "All module outputs"
  value = {
    lambda_arn           = module.security_notifications.lambda_function_arn
    lambda_name          = module.security_notifications.lambda_function_name
    lambda_role          = module.security_notifications.lambda_role_arn
    log_group            = module.security_notifications.cloudwatch_log_group
    sqs_queue            = module.security_notifications.sqs_queue_url
    dlq                  = module.security_notifications.dlq_url
    eventbridge_rule     = module.security_notifications.eventbridge_rule_arn
    alarms               = module.security_notifications.alarm_names
  }
}

output "monitoring_commands" {
  description = "Useful commands for monitoring"
  value = <<-EOT
    # View logs
    aws logs tail ${module.security_notifications.cloudwatch_log_group} --follow

    # Test function
    aws lambda invoke --function-name ${module.security_notifications.lambda_function_name} --payload '{}' response.json

    # Check DLQ
    aws sqs get-queue-attributes --queue-url ${module.security_notifications.dlq_url} --attribute-names All

    # View metrics
    aws cloudwatch get-metric-statistics \\
      --namespace AWS/Lambda \\
      --metric-name Invocations \\
      --dimensions Name=FunctionName,Value=${module.security_notifications.lambda_function_name} \\
      --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \\
      --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \\
      --period 300 \\
      --statistics Sum
  EOT
}

