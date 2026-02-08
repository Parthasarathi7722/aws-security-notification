# Deployment Guide

Complete guide for deploying the AWS Security Notification System.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [CloudFormation Deployment](#cloudformation)
4. [Terraform Deployment](#terraform)
5. [Manual Deployment](#manual)
6. [Post-Deployment](#post-deployment)
7. [Troubleshooting](#troubleshooting)

---

## Overview

The AWS Security Notification System can be deployed using two methods:

| Method | Best For | Deployment Time | Difficulty |
|--------|----------|-----------------|------------|
| CloudFormation | AWS-native IaC | 5 minutes | Easy |
| Terraform | Multi-cloud IaC | 5 minutes | Easy |
| Manual | Learning/Testing | 10 minutes | Medium |

---

## Prerequisites

### Required

- AWS Account with appropriate permissions
- Slack webhook URL ([create one](https://api.slack.com/messaging/webhooks))
- S3 bucket for Lambda deployment
- AWS CLI installed and configured

### Optional

- Terraform >= 1.0 (for Terraform deployment)
- Git (to clone repository)

---- View resources in CloudFormation console
- Update parameters by updating the stack
- Monitor via CloudWatch

---

## CloudFormation Deployment {#cloudformation}

**Best for AWS-native deployments and CI/CD**

### Quick Deploy (5 minutes)

```bash
# 1. Clone repository
git clone https://github.com/Parthasarathi7722/aws-security-notification.git
cd aws-security-notification

# 2. Build package
make package

# 3. Upload to S3 (replace with your bucket)
aws s3 cp function.zip s3://YOUR-BUCKET/

# 4. Deploy stack
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name security-notifications \
  --parameter-overrides \
    LambdaCodeBucket=YOUR-BUCKET \
    LambdaCodeKey=function.zip \
    SlackWebhookUrl=https://hooks.slack.com/YOUR/WEBHOOK \
    AccountName="Production" \
  --capabilities CAPABILITY_IAM
```

### With Optional Services

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name security-notifications \
  --parameter-overrides \
    LambdaCodeBucket=YOUR-BUCKET \
    LambdaCodeKey=function.zip \
    SlackWebhookUrl=https://hooks.slack.com/YOUR/WEBHOOK \
    AccountName="Production" \
    EnableGuardDuty=true \
    EnableSecurityHub=true \
    EnableConfig=true \
  --capabilities CAPABILITY_IAM
```

### Parameters Reference

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| LambdaCodeBucket | S3 bucket with Lambda code | - | Yes |
| LambdaCodeKey | S3 key for package | function.zip | No |
| SlackWebhookUrl | Slack webhook URL | - | Yes |
| AccountName | AWS account name | Unknown Account | No |
| WhitelistResources | ARN patterns to ignore | "" | No |
| CriticalEvents | Critical event names | "" | No |
| EnableGuardDuty | Enable GuardDuty | false | No |
| EnableSecurityHub | Enable Security Hub | false | No |
| EnableConfig | Enable AWS Config | false | No |
| EnableECS | Enable ECS monitoring | true | No |
| EnableEKS | Enable EKS monitoring | true | No |

### Update Stack

```bash
# Update template or parameters
aws cloudformation update-stack \
  --stack-name security-notifications \
  --template-body file://template.yaml \
  --parameters \
    ParameterKey=SlackWebhookUrl,UsePreviousValue=true \
    ParameterKey=EnableGuardDuty,ParameterValue=true \
  --capabilities CAPABILITY_IAM
```

---

## Terraform Deployment {#terraform}

**Best for Infrastructure as Code and multi-cloud**

### Prerequisites

```bash
# Install Terraform
brew install terraform  # macOS
# OR
choco install terraform # Windows

# Verify
terraform version
```

### Quick Deploy

```bash
# 1. Clone and build
git clone https://github.com/Parthasarathi7722/aws-security-notification.git
cd aws-security-notification
make package

# 2. Create terraform.tfvars
cat > terraform/terraform.tfvars << EOF
slack_webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
EOF

# 3. Deploy
cd terraform
terraform init
terraform plan
terraform apply
```

### Advanced Configuration

Create `terraform/terraform.tfvars`:

```hcl
slack_webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Enable services
enable_guardduty    = true
enable_security_hub = true
enable_config       = true

# Customize
function_name      = "SecurityMonitoring"
account_name       = "Production"
lambda_memory_size = 512
log_retention_days = 30

# Security
whitelist_resources = [
  "arn:aws:iam::*:role/ServiceRole*"
]

critical_events = [
  "CreateUser",
  "DeleteUser",
  "DeleteRole"
]

# Tags
tags = {
  Environment = "Production"
  Team        = "Security"
}
```

### Module Usage

Use as a module in your existing Terraform:

```hcl
module "security_notifications" {
  source = "github.com/Parthasarathi7722/aws-security-notification//terraform"

  slack_webhook_url = var.slack_webhook_url
  enable_guardduty  = true
  enable_security_hub = true
  
  tags = var.common_tags
}
```

### Examples

See `examples/` directory:

```bash
# Basic example
cd examples/basic
terraform init
terraform apply

# Advanced example
cd examples/advanced
terraform init
terraform apply
```

---

## Manual Deployment {#manual}

**Best for learning and testing**

### Steps

1. **Build Package**
   ```bash
   make package
   ```

2. **Create IAM Role**
   - AWS Console → IAM → Roles
   - Create role for Lambda
   - Attach policies (see template.yaml for required permissions)

3. **Create Lambda Function**
   - AWS Console → Lambda → Create function
   - Upload `function.zip`
   - Handler: `SecOps_notification.lambda_handler`
   - Runtime: Python 3.11
   - Set environment variables (see Configuration section)

4. **Create SQS Queue**
   - AWS Console → SQS → Create queue
   - Standard queue
   - Enable dead letter queue

5. **Create EventBridge Rule**
   - AWS Console → EventBridge → Create rule
   - Event pattern (see template.yaml)
   - Target: SQS queue

6. **Configure Lambda Trigger**
   - Lambda → Add trigger
   - Select SQS queue
   - Batch size: 10

### Environment Variables

```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
ACCOUNT_NAME=Production
WHITELIST_RESOURCES=arn:aws:iam::*:role/ServiceRole*
CRITICAL_EVENTS=CreateUser,DeleteUser,DeleteRole
ENABLE_GUARDDUTY=false
ENABLE_SECURITYHUB=false
ENABLE_CONFIG=false
ENABLE_ECS=true
ENABLE_EKS=true
LOG_LEVEL=INFO
MAX_RETRIES=3
RETRY_DELAY_SECONDS=2
RATE_LIMIT_PER_MINUTE=30
MAX_SLACK_MESSAGE_LENGTH=3000
```

---

## Post-Deployment {#post-deployment}

### Verification

```bash
# Check Lambda function
aws lambda get-function --function-name SecurityOpsNotificationSystem

# Check logs
aws logs tail /aws/lambda/SecurityOpsNotificationSystem --follow

# Manual test
aws lambda invoke \
  --function-name SecurityOpsNotificationSystem \
  --payload '{}' \
  response.json

# Trigger real event
aws iam create-user --user-name test-security-alert-$(date +%s)
# Check Slack for notification
```

### Monitoring

```bash
# View metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=SecurityOpsNotificationSystem \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum

# Check DLQ
aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name security-notifications-dlq --query 'QueueUrl' --output text) \
  --attribute-names ApproximateNumberOfMessages
```

### Set Up Alarms

```bash
# Lambda errors
aws cloudwatch put-metric-alarm \
  --alarm-name SecurityNotification-Errors \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --dimensions Name=FunctionName,Value=SecurityOpsNotificationSystem

# DLQ messages
aws cloudwatch put-metric-alarm \
  --alarm-name SecurityNotification-DLQ \
  --metric-name ApproximateNumberOfMessagesVisible \
  --namespace AWS/SQS \
  --statistic Average \
  --period 60 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --dimensions Name=QueueName,Value=security-notifications-dlq
```

---

## Troubleshooting {#troubleshooting}

### No Notifications

**Problem**: Slack not receiving notifications

**Solutions**:
1. Verify webhook URL is correct
   ```bash
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"Test"}' \
     YOUR_WEBHOOK_URL
   ```

2. Check Lambda logs
   ```bash
   aws logs tail /aws/lambda/SecurityOpsNotificationSystem --follow
   ```

3. Verify Lambda has internet access (if in VPC, needs NAT Gateway)

4. Check EventBridge rule is enabled
   ```bash
   aws events describe-rule --name security-notifications-rule
   ```

### Permission Errors

**Problem**: IAM permission denied

**Solutions**:
1. Verify IAM role has correct policies
   ```bash
   aws iam get-role-policy \
     --role-name SecurityNotificationLambdaRole \
     --policy-name NotificationLambdaPolicy
   ```

2. Check service is enabled (e.g., GuardDuty)
3. Verify account has access to service

### High Error Rate

**Problem**: Many Lambda errors

**Solutions**:
1. Check DLQ for failed messages
   ```bash
   aws sqs receive-message \
     --queue-url $(aws sqs get-queue-url --queue-name security-notifications-dlq --query 'QueueUrl' --output text)
   ```

2. Review error patterns in logs
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/lambda/SecurityOpsNotificationSystem \
     --filter-pattern "ERROR"
   ```

3. Increase Lambda timeout if needed
4. Check rate limiting settings

### Timeout Errors

**Problem**: Lambda timing out

**Solutions**:
1. Increase timeout (default 60s)
2. Disable optional services to reduce execution time
3. Check for slow API calls in logs

### Rate Limiting

**Problem**: Slack rate limiting errors

**Solutions**:
1. Check rate limit setting (default 30/min)
2. Increase delay between retries
3. Aggregate more events before sending

---

## Cost Estimation

### Typical Monthly Costs (10,000 events)

| Service | Cost |
|---------|------|
| Lambda (256MB, 60s avg) | $0.20 |
| SQS (100K requests) | $0.04 |
| CloudWatch Logs (5GB) | $0.50 |
| EventBridge (Free tier) | $0.00 |
| **Total** | **~$0.74/month** |

### With All Services Enabled

| Service | Cost |
|---------|------|
| Lambda (512MB, 90s avg) | $0.40 |
| SQS | $0.05 |
| CloudWatch Logs | $0.50 |
| CloudWatch Alarms (2) | $0.20 |
| **Total** | **~$1.15/month** |

---

## Next Steps

1. **Test the system**: Trigger events and verify notifications
2. **Enable services**: Add GuardDuty, Security Hub as needed
3. **Customize**: Update whitelists and critical events
4. **Monitor**: Set up CloudWatch dashboard
5. **Document**: Add to runbooks and incident response plans

---

## Support

- **Issues**: [GitHub Issues](https://github.com/Parthasarathi7722/aws-security-notification/issues)
- **Documentation**: [README](../README.md)
- **Examples**: [examples/](../examples/)
- **Terraform**: [terraform/](../terraform/)

---

**Version**: 1.0.0  
**Last Updated**: December 2, 2025  
**Status**: Production Ready

