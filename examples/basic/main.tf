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
}

variable "slack_webhook_url" {
  description = "Slack webhook URL"
  type        = string
  sensitive   = true
}

output "lambda_function_name" {
  description = "Name of the deployed Lambda function"
  value       = module.security_notifications.lambda_function_name
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group for monitoring"
  value       = module.security_notifications.cloudwatch_log_group
}

