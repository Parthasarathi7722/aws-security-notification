variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  sensitive   = true
}

variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
  default     = "SecurityOpsNotificationSystem"
}

variable "lambda_role_name" {
  description = "Name of the Lambda execution role"
  type        = string
  default     = "SecurityNotificationLambdaRole"
}

variable "deployment_package_path" {
  description = "Path to the Lambda deployment package"
  type        = string
  default     = "../function.zip"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 60
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 30
}

variable "account_name" {
  description = "Friendly name for the AWS account"
  type        = string
  default     = "AWS Account"
}

variable "whitelist_resources" {
  description = "List of ARN patterns to whitelist"
  type        = list(string)
  default     = []
}

variable "critical_events" {
  description = "List of critical event names"
  type        = list(string)
  default     = ["CreateUser", "DeleteUser", "DeleteRole", "PutBucketPolicy"]
}

variable "enable_guardduty" {
  description = "Enable GuardDuty monitoring"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub monitoring"
  type        = bool
  default     = true
}

variable "enable_iam" {
  description = "Enable IAM monitoring"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail monitoring"
  type        = bool
  default     = true
}

variable "log_level" {
  description = "Log level for Lambda function"
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR"], var.log_level)
    error_message = "Log level must be DEBUG, INFO, WARNING, or ERROR"
  }
}

variable "max_retries" {
  description = "Maximum retry attempts for Slack notifications"
  type        = number
  default     = 3
}

variable "retry_delay_seconds" {
  description = "Delay between retries in seconds"
  type        = number
  default     = 2
}

variable "rate_limit_per_minute" {
  description = "Maximum Slack messages per minute"
  type        = number
  default     = 30
}

variable "max_message_length" {
  description = "Maximum Slack message length"
  type        = number
  default     = 3000
}

variable "monitored_events" {
  description = "List of AWS events to monitor"
  type        = list(string)
  default = [
    "CreateUser",
    "DeleteUser",
    "CreateRole",
    "DeleteRole",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "ConsoleLogin"
  ]
}


variable "additional_environment_variables" {
  description = "Additional environment variables for Lambda"
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "SecurityNotifications"
    ManagedBy   = "Terraform"
    Environment = "Production"
  }
}

