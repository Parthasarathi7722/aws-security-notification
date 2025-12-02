# Terraform Module - AWS Security Notification System

Deploy the AWS Security Notification System using Terraform with complete infrastructure as code.

## Features

- **Complete Infrastructure**: Lambda, IAM, EventBridge, SQS, CloudWatch
- **Configurable**: All options exposed as variables
- **Production Ready**: Best practices, alarms, DLQ, retry logic
- **Multi-Service**: Support for GuardDuty, Security Hub, Config, ECS, EKS
- **Monitoring**: CloudWatch Logs, Metrics, and Alarms

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured
- Deployment package built (`make package` in parent directory)

## Quick Start

### Basic Deployment

```hcl
module "security_notifications" {
  source = "github.com/Parthasarathi7722/aws-security-notification//terraform"

  slack_webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
}
```

### Production Configuration

```hcl
module "security_notifications" {
  source = "github.com/Parthasarathi7722/aws-security-notification//terraform"

  # Required
  slack_webhook_url = var.slack_webhook_url

  # Optional Services
  enable_guardduty    = true
  enable_security_hub = true
  enable_config       = true
  enable_ecs          = true
  enable_eks          = true

  # Customization
  function_name      = "SecurityMonitoring"
  account_name       = "Production"
  lambda_memory_size = 512
  lambda_timeout     = 90
  log_retention_days = 30

  # Security
  whitelist_resources = [
    "arn:aws:iam::*:role/ServiceRole*",
    "arn:aws:iam::123456789012:user/admin"
  ]

  critical_events = [
    "CreateUser",
    "DeleteUser",
    "DeleteRole",
    "PutBucketPolicy"
  ]

  # Monitoring
  enable_alarms = true

  # Tags
  tags = {
    Environment = "Production"
    Team        = "Security"
    Compliance  = "SOC2"
  }
}
```

## Usage

### 1. Build Deployment Package

```bash
# From repository root
make package
```

### 2. Create terraform.tfvars

```hcl
slack_webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
enable_guardduty  = true
```

### 3. Deploy

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | ~> 5.0 |

## Providers

| Name | Version |
|------|---------|
| aws | ~> 5.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| slack_webhook_url | Slack webhook URL for notifications | `string` | n/a | yes |
| function_name | Name of the Lambda function | `string` | `"SecurityOpsNotificationSystem"` | no |
| account_name | Friendly name for AWS account | `string` | `"AWS Account"` | no |
| deployment_package_path | Path to Lambda deployment package | `string` | `"../function.zip"` | no |
| lambda_timeout | Lambda timeout in seconds | `number` | `60` | no |
| lambda_memory_size | Lambda memory in MB | `number` | `256` | no |
| log_retention_days | CloudWatch Logs retention days | `number` | `30` | no |
| enable_guardduty | Enable GuardDuty monitoring | `bool` | `false` | no |
| enable_security_hub | Enable Security Hub monitoring | `bool` | `false` | no |
| enable_config | Enable AWS Config monitoring | `bool` | `false` | no |
| enable_ecs | Enable ECS monitoring | `bool` | `true` | no |
| enable_eks | Enable EKS monitoring | `bool` | `true` | no |
| whitelist_resources | List of ARN patterns to whitelist | `list(string)` | `[]` | no |
| critical_events | List of critical event names | `list(string)` | `["CreateUser", "DeleteUser", ...]` | no |
| monitored_events | List of AWS events to monitor | `list(string)` | `[...]` | no |
| enable_alarms | Enable CloudWatch alarms | `bool` | `true` | no |
| log_level | Log level (DEBUG, INFO, WARNING, ERROR) | `string` | `"INFO"` | no |
| max_retries | Max retry attempts for Slack | `number` | `3` | no |
| rate_limit_per_minute | Max Slack messages per minute | `number` | `30` | no |
| tags | Tags to apply to all resources | `map(string)` | `{...}` | no |

## Outputs

| Name | Description |
|------|-------------|
| lambda_function_arn | ARN of the Lambda function |
| lambda_function_name | Name of the Lambda function |
| lambda_role_arn | ARN of the Lambda execution role |
| cloudwatch_log_group | CloudWatch Log Group name |
| sqs_queue_url | URL of the notification queue |
| sqs_queue_arn | ARN of the notification queue |
| dlq_url | URL of the dead letter queue |
| dlq_arn | ARN of the dead letter queue |
| eventbridge_rule_arn | ARN of the EventBridge rule |
| alarm_names | Names of CloudWatch alarms |

## Resources Created

This module creates:

- **Lambda Function**: Main security notification handler
- **IAM Role & Policy**: Least privilege execution role
- **SQS Queue**: Event buffer with DLQ
- **EventBridge Rule**: Capture security events
- **CloudWatch Log Group**: Lambda logs with retention
- **CloudWatch Alarms**: Lambda errors and DLQ messages (optional)

## Examples

See the `examples/` directory:

- **basic**: Minimal configuration
- **advanced**: Production setup with all features

## Monitoring

### View Logs

```bash
# Using AWS CLI
aws logs tail /aws/lambda/SecurityOpsNotificationSystem --follow

# Using Terraform
terraform output cloudwatch_log_group | xargs -I {} aws logs tail {} --follow
```

### Check Metrics

```bash
# Lambda invocations
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=SecurityOpsNotificationSystem \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

### Alarms

If `enable_alarms = true`, alarms are created for:
- Lambda function errors (> 5 errors in 5 minutes)
- Dead letter queue messages (> 0 messages)

## Troubleshooting

### No notifications received

```bash
# Check Lambda logs
terraform output cloudwatch_log_group | xargs -I {} aws logs tail {}

# Test Lambda manually
terraform output lambda_function_name | xargs -I {} aws lambda invoke \
  --function-name {} \
  --payload '{}' \
  response.json
```

### Permission errors

Verify IAM role has required permissions:

```bash
terraform output lambda_role_arn | xargs -I {} aws iam get-role --role-name {}
```

### Deployment package not found

Ensure you built the package:

```bash
cd .. && make package && cd terraform
```

## Updating

To update the Lambda code:

```bash
# Rebuild package
cd .. && make package && cd terraform

# Apply changes
terraform apply
```

To update configuration only:

```bash
# Edit terraform.tfvars
# Apply changes
terraform apply
```

## Destroying

To remove all resources:

```bash
terraform destroy
```

**Note**: This will delete all logs and queued messages. Export any needed data first.

## Integration with Existing Infrastructure

### Use existing SQS queue

Currently not supported. The module creates its own queue for isolation.

### Custom EventBridge rules

You can add additional EventBridge rules that target the module's SQS queue:

```hcl
resource "aws_cloudwatch_event_rule" "custom_rule" {
  name        = "custom-security-rule"
  description = "Custom security events"

  event_pattern = jsonencode({
    source = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
  })
}

resource "aws_cloudwatch_event_target" "custom_target" {
  rule      = aws_cloudwatch_event_rule.custom_rule.name
  target_id = "SendToSecurityQueue"
  arn       = module.security_notifications.sqs_queue_arn
}
```

## Cost Estimation

Estimated monthly costs (us-east-1):

- Lambda: ~$0.20 (1M requests, 256MB, 60s avg)
- SQS: ~$0.04 (100K requests)
- CloudWatch Logs: ~$0.50 (5GB ingestion)
- EventBridge: $0.00 (Free tier)

**Total: ~$0.74/month**

## Security Considerations

- Slack webhook URL is marked as sensitive
- IAM role follows least privilege principle
- SQS messages encrypted at rest (AWS managed keys)
- Lambda logs retained for audit trail
- Dead letter queue for failed processing

## Support

- **Issues**: [GitHub Issues](https://github.com/Parthasarathi7722/aws-security-notification/issues)
- **Documentation**: [Main README](../README.md)
- **Examples**: [examples/](../examples/)

## License

MIT License - See [LICENSE](../LICENSE)

