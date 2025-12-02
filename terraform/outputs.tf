output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.security_notification.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.security_notification.function_name
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_execution_role.arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "sqs_queue_url" {
  description = "URL of the notification SQS queue"
  value       = aws_sqs_queue.notification_queue.url
}

output "sqs_queue_arn" {
  description = "ARN of the notification SQS queue"
  value       = aws_sqs_queue.notification_queue.arn
}

output "dlq_url" {
  description = "URL of the dead letter queue"
  value       = aws_sqs_queue.notification_dlq.url
}

output "dlq_arn" {
  description = "ARN of the dead letter queue"
  value       = aws_sqs_queue.notification_dlq.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.security_events.arn
}

output "alarm_names" {
  description = "Names of CloudWatch alarms (if enabled)"
  value       = var.enable_alarms ? [aws_cloudwatch_metric_alarm.lambda_errors[0].alarm_name, aws_cloudwatch_metric_alarm.dlq_messages[0].alarm_name] : []
}

