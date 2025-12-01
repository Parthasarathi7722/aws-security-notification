# AWS Security Notification System

Real-time Slack notifications for AWS security events with retry logic, rate limiting, and CloudWatch metrics.

## Features

- **Real-time Alerts** - Instant Slack notifications for security events
- **Smart Retry** - Exponential backoff for failed deliveries
- **Rate Limiting** - Prevents Slack API throttling (30 msg/min)
- **Event Filtering** - Whitelist support with wildcard patterns
- **Multi-Service** - IAM, S3, EC2, GuardDuty, SecurityHub, Config, ECS, EKS
- **CloudWatch Metrics** - Track events, notifications, and errors
- **Cost Efficient** - ~$0.84/month for 10K events

## Quick Start

### 1. Prerequisites
- AWS Account with appropriate permissions
- Slack webhook URL ([create one here](https://api.slack.com/messaging/webhooks))
- S3 bucket for Lambda deployment

### 2. Deploy

```bash
# Package Lambda function
zip -r function.zip SecOps_notification.py requests/ urllib3/ certifi/ charset_normalizer/ idna/

# Upload to S3
aws s3 cp function.zip s3://YOUR_BUCKET/

# Deploy CloudFormation stack
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name security-notifications \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    LambdaCodeBucket=YOUR_BUCKET \
    LambdaCodeKey=function.zip \
    SlackWebhookUrl=https://hooks.slack.com/services/XXX/YYY/ZZZ \
    AccountName="Production"
```

### 3. Test

```bash
# Trigger a test event
aws iam create-user --user-name test-security-alert
aws iam delete-user --user-name test-security-alert

# Check Slack for notification
```

## Configuration

### Required Parameters
- **SlackWebhookUrl** - Your Slack webhook URL
- **LambdaCodeBucket** - S3 bucket containing Lambda code
- **LambdaCodeKey** - S3 key for Lambda package (default: `function.zip`)

### Optional Parameters
- **AccountName** - Friendly name for AWS account (default: `AWS Account`)
- **WhitelistResources** - Comma-separated ARN patterns to ignore
- **CriticalEvents** - Comma-separated critical event names
- **EnableGuardDuty** - Enable GuardDuty integration (`true`/`false`)
- **EnableSecurityHub** - Enable Security Hub integration (`true`/`false`)
- **EnableConfig** - Enable AWS Config integration (`true`/`false`)
- **EnableECS** - Enable ECS monitoring (`true`/`false`)
- **EnableEKS** - Enable EKS monitoring (`true`/`false`)

### Environment Variables
Configure Lambda function behavior:
- `SLACK_WEBHOOK_URL` - Slack webhook (required)
- `ACCOUNT_NAME` - Account display name
- `WHITELIST_RESOURCES` - ARN patterns to ignore (comma-separated)
- `CRITICAL_EVENTS` - Critical event names (comma-separated)
- `MAX_RETRIES` - Max retry attempts (default: 3)
- `RETRY_DELAY_SECONDS` - Retry delay (default: 2)
- `RATE_LIMIT_PER_MINUTE` - Message rate limit (default: 30)
- `MAX_SLACK_MESSAGE_LENGTH` - Max message size (default: 3000)

## Monitored Events

### Core Services
- **IAM** - User/role changes, policy modifications
- **S3** - Bucket policy changes
- **EC2** - Security group modifications
- **CloudTrail** - Trail configuration changes

### Optional Services (Feature Flags)
- **GuardDuty** - High-severity threat findings
- **Security Hub** - Critical/high-severity findings
- **AWS Config** - Compliance rule violations
- **ECS** - Container security issues
- **EKS** - Kubernetes security issues

## Whitelisting

Use wildcards to filter events:

```bash
# Whitelist all ServiceRoles
WHITELIST_RESOURCES="arn:aws:iam::*:role/ServiceRole*"

# Whitelist multiple patterns
WHITELIST_RESOURCES="arn:aws:iam::123:role/Admin*,arn:aws:iam::*:role/Service*"
```

## CloudWatch Metrics

Published to namespace `SecurityNotifications`:
- `EventsProcessed` - Total events handled
- `EventsFiltered` - Events filtered by whitelist
- `NotificationsSent` - Successful Slack notifications
- `NotificationsFailed` - Failed notifications
- `Errors` - Error count

## Monitoring

### View Logs
```bash
aws logs tail /aws/lambda/security-notifications-notification-lambda --follow
```

### Query Errors
```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/security-notifications-notification-lambda \
  --filter-pattern "ERROR"
```

### Check Metrics
```bash
aws cloudwatch get-metric-statistics \
  --namespace SecurityNotifications \
  --metric-name EventsProcessed \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

## Troubleshooting

### No Notifications
1. Check Slack webhook URL is correct
2. Verify Lambda has internet access
3. Check CloudWatch Logs for errors
4. Verify EventBridge rule is enabled

### High Error Rate
1. Check dead letter queue for failed messages
2. Review CloudWatch Logs
3. Verify IAM permissions
4. Check service availability (GuardDuty, Security Hub, etc.)

### Rate Limiting
- Default: 30 messages per minute
- Increase `RATE_LIMIT_PER_MINUTE` if needed
- Or aggregate more events with longer visibility timeout

## Architecture

```
AWS Services → EventBridge → SQS Queue → Lambda → Slack
                    ↓                        ↓
                 Filter               CloudWatch
                                    (Logs + Metrics)
```

## Cost Estimate

For 10,000 events/month:
- EventBridge: $0.10
- SQS: $0.04
- Lambda: $0.20
- CloudWatch Logs: $0.50
- **Total: ~$0.84/month**

## Security Best Practices

- Principle of least privilege IAM
- No hardcoded credentials
- Encryption in transit (HTTPS)
- Encryption at rest (SQS)
- CloudWatch audit logs
- MFA detection
- Root account monitoring

## Updating

### Update Lambda Code
```bash
zip -r function.zip SecOps_notification.py requests/ urllib3/ certifi/ charset_normalizer/ idna/
aws s3 cp function.zip s3://YOUR_BUCKET/
aws lambda update-function-code \
  --function-name security-notifications-notification-lambda \
  --s3-bucket YOUR_BUCKET \
  --s3-key function.zip
```

### Update Configuration
```bash
aws lambda update-function-configuration \
  --function-name security-notifications-notification-lambda \
  --environment Variables="{SLACK_WEBHOOK_URL=new-url,...}"
```

## Examples

### Enable All Security Services
```bash
aws cloudformation update-stack \
  --stack-name security-notifications \
  --use-previous-template \
  --parameters \
    ParameterKey=EnableGuardDuty,ParameterValue=true \
    ParameterKey=EnableSecurityHub,ParameterValue=true \
    ParameterKey=EnableConfig,ParameterValue=true \
  --capabilities CAPABILITY_IAM
```

### Add Critical Events
```bash
aws lambda update-function-configuration \
  --function-name security-notifications-notification-lambda \
  --environment Variables="{...,CRITICAL_EVENTS=CreateUser;DeleteUser;DeleteRole}"
```

## Support

- Documentation: This README
- Issues: Check CloudWatch Logs
- Questions: Review troubleshooting section

## License

MIT License - See LICENSE file

---

**Version**: 2.1.0 (Streamlined)  
**Status**: Production Ready  
**Setup Time**: 5-10 minutes  
**Monthly Cost**: <$1  

