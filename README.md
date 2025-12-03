# AWS Security Notification System

Real-time Slack notifications for AWS security events with retry logic, rate limiting, and CloudWatch metrics.

![AWS](https://img.shields.io/badge/AWS-CloudFormation-orange?logo=amazon-aws)
![Python](https://img.shields.io/badge/python-3.11-blue?logo=python)
![Terraform](https://img.shields.io/badge/Terraform-1.6+-purple?logo=terraform)
![License](https://img.shields.io/badge/license-MIT-green)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

## Features

- **Real-time Alerts** - Instant Slack notifications for security events
- **Smart Retry** - Exponential backoff for failed deliveries
- **Rate Limiting** - Prevents Slack API throttling (30 msg/min)
- **Event Filtering** - Whitelist support with wildcard patterns
- **Multi-Service** - IAM, S3, EC2, GuardDuty, SecurityHub, Config, ECS, EKS
- **CloudWatch Metrics** - Track events, notifications, and errors
- **Cost Efficient** - ~$0.84/month for 10K events

## Distribution Options

This project is available through three supported methods:
- **Python Package**: Use the core module in your own projects or custom runners
- **CloudFormation**: AWS-native deployment via a single template
- **Terraform**: Full infrastructure as code module, with examples

---

## Option 1: Python Package (Library Use)

Install locally from source:

```bash
# From repository root
pip install .
```

Or install directly from GitHub (without cloning):

```bash
pip install "git+https://github.com/Parthasarathi7722/aws-security-notification.git#egg=aws_security_notification"
```

Use in your own runner:

```python
from aws_security_notification import lambda_handler

# Example local invocation
event = {"Records": []}
resp = lambda_handler(event, context=None)
print(resp)
```

Notes:
- The package exports the Lambda handler and core logic for reuse.
- For local runs, you must set environment variables (SLACK_WEBHOOK_URL, etc.).

---

## Option 2: CloudFormation (AWS Native)

```bash
# Quick deploy
git clone https://github.com/Parthasarathi7722/aws-security-notification.git
cd aws-security-notification
make package
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name security-notifications \
  --parameter-overrides SlackWebhookUrl=YOUR_WEBHOOK_URL \
  --capabilities CAPABILITY_IAM
```

For advanced parameters and usage, see the full Configuration section below.

---

## Option 3: Terraform (Infrastructure as Code)

```hcl
module "security_notifications" {
  source = "github.com/Parthasarathi7722/aws-security-notification//terraform"

  slack_webhook_url   = var.slack_webhook_url
  enable_guardduty    = true
  enable_security_hub = true
}
```

See the **Terraform Module** docs: `terraform/README.md` and examples under `examples/`.

---

## Quick Start (Manual)

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

## Deployment Guide and Examples

- Detailed steps: `docs/DEPLOYMENT.md`
- Terraform module: `terraform/README.md`
- Examples: `examples/basic` and `examples/advanced`

## Discoverability (Without AWS SAR)

- Publish GitHub releases with attached `function.zip` for easy download
- Include CloudFormation commands in release notes
- Use GitHub topics: `aws-security`, `slack-notifications`, `serverless`, `cloudformation`, `terraform`, `lambda`
- Provide a short README intro and badges at the top (already included)

## Support

- Documentation: This README and `docs/DEPLOYMENT.md`
- Issues: GitHub Issues
- Questions: Review troubleshooting section

## Current Capabilities

### Monitored AWS Services

**Always Active:**
- **IAM** - User/role creation, deletion, policy changes
- **S3** - Bucket policy modifications, access changes
- **EC2** - Security group modifications, ingress/egress rules
- **CloudTrail** - Trail configuration changes, logging status
- **KMS** - Key creation, deletion, policy changes
- **Secrets Manager** - Secret creation, deletion, rotation

**Optional (Feature Flags):**
- **GuardDuty** - High-severity threat findings (enable_guardduty=true)
- **Security Hub** - Critical/high security findings (enable_securityhub=true)
- **AWS Config** - Compliance rule violations (enable_config=true)
- **ECS** - Cluster status, privileged containers (enable_ecs=true)
- **EKS** - Cluster status, public access, logging (enable_eks=true)

### Security Checks Performed

**Identity & Access Management:**
- Root account usage detection
- MFA authentication status
- User and role modifications
- Policy attachments/detachments
- Permission boundary changes

**Network Security:**
- Security group rule changes (0.0.0.0/0 detection)
- VPC configuration modifications
- Network ACL changes
- Public access configurations

**Data Security:**
- S3 bucket policy changes
- Encryption status modifications
- Public access block changes
- KMS key policy updates
- Secret rotation status

**Compliance & Configuration:**
- Config rule compliance status
- Security Hub findings
- GuardDuty threat detections
- Resource configuration changes

**Container Security:**
- ECS privileged container detection
- EKS public endpoint exposure
- EKS logging configuration
- Container image vulnerabilities (via Security Hub)

### Alert Features

**Notification Capabilities:**
- Real-time Slack notifications
- Critical alert highlighting
- Event aggregation (reduce alert fatigue)
- Retry logic (3 attempts with exponential backoff)
- Rate limiting (30 messages/minute)
- Message truncation for long events

**Filtering & Customization:**
- Whitelist support with wildcard patterns
- Critical event classification
- Resource-based filtering
- Event type filtering
- Account-specific naming

## Adding New Security Checks

### Quick Guide

To add a new AWS service or security check:

#### 1. Add AWS Client (if new service)
```python
# In SecOps_notification.py initialization section
new_service_client = boto3.client("new-service")
```

#### 2. Create Check Function
```python
def get_newservice_security_events():
    """Get NewService security issues."""
    if not config.enable_newservice:  # Add feature flag
        return []
    
    events = []
    try:
        # Query the service
        response = new_service_client.describe_resources()
        
        # Check for security issues
        for resource in response.get('Resources', []):
            if resource.get('SecurityIssue'):
                events.append({
                    'type': 'NEWSERVICE_ISSUE',
                    'severity': 'HIGH',
                    'resource': resource.get('ResourceId'),
                    'description': f"Security issue detected in {resource.get('ResourceId')}"
                })
        
        return events
    except ClientError as e:
        logger.error(f"Error checking NewService: {str(e)}")
        return []
    except Exception as e:
        metrics['errors'] += 1
        return []
```

#### 3. Add to Lambda Handler
```python
# In lambda_handler function, add:
if config.enable_newservice:
    newservice_events = get_newservice_security_events()
    if newservice_events:
        msg = f"*NewService Security - {config.account_name}*\n"
        for event in newservice_events:
            msg += f"\n{event['description']}"
        send_to_slack(msg, any(e['severity'] == 'HIGH' for e in newservice_events))
```

#### 4. Add Environment Variable
```python
# In Config class:
self.enable_newservice = os.getenv("ENABLE_NEWSERVICE", "false").lower() == "true"
```

#### 5. Update CloudFormation
```yaml
# In template.yaml Parameters section:
EnableNewService:
  Type: String
  Description: Enable NewService monitoring (true/false)
  Default: 'false'
  AllowedValues:
    - 'true'
    - 'false'

# In Lambda Environment Variables:
ENABLE_NEWSERVICE: !Ref EnableNewService
```

#### 6. Update IAM Permissions
```yaml
# In NotificationLambdaPolicy:
- Effect: Allow
  Action:
    - newservice:DescribeResources
    - newservice:ListResources
  Resource: '*'
```

### Example: Adding RDS Monitoring

Here's a complete example for adding RDS database monitoring:

```python
# 1. Add client
rds_client = boto3.client("rds")

# 2. Create check function
def get_rds_security_events():
    """Get RDS security issues."""
    if not config.enable_rds:
        return []
    
    events = []
    try:
        # Check for public databases
        response = rds_client.describe_db_instances()
        for db in response.get('DBInstances', []):
            if db.get('PubliclyAccessible'):
                events.append({
                    'type': 'RDS_PUBLIC_ACCESS',
                    'severity': 'HIGH',
                    'database': db.get('DBInstanceIdentifier'),
                    'description': f"Database {db.get('DBInstanceIdentifier')} is publicly accessible"
                })
            
            # Check for unencrypted databases
            if not db.get('StorageEncrypted'):
                events.append({
                    'type': 'RDS_UNENCRYPTED',
                    'severity': 'HIGH',
                    'database': db.get('DBInstanceIdentifier'),
                    'description': f"Database {db.get('DBInstanceIdentifier')} is not encrypted"
                })
        
        return events
    except Exception as e:
        logger.error(f"RDS check error: {str(e)}")
        return []

# 3. Add to lambda_handler
if config.enable_rds:
    rds_events = get_rds_security_events()
    if rds_events:
        msg = f"*RDS Security - {config.account_name}*\n"
        for event in rds_events:
            msg += f"\n{event['description']}"
        send_to_slack(msg, any(e['severity'] == 'HIGH' for e in rds_events))
```

### Adding EventBridge Rules

To monitor new event types, update the EventBridge rule in `template.yaml`:

```yaml
SecurityEventRule:
  Properties:
    EventPattern:
      source:
        - aws.rds  # Add new service
      detail-type:
        - AWS API Call via CloudTrail
      detail:
        eventName:
          - CreateDBInstance
          - DeleteDBInstance
          - ModifyDBInstance
```

### Testing New Checks

1. **Test locally** (if possible):
```python
# Create test script
if __name__ == "__main__":
    events = get_newservice_security_events()
    print(f"Found {len(events)} security issues")
    for event in events:
        print(f"  - {event['description']}")
```

2. **Deploy and test**:
```bash
# Update Lambda
make update BUCKET=your-bucket

# Trigger test event
aws newservice create-resource --name test-resource

# Check CloudWatch Logs
make logs
```

3. **Verify Slack notification** appears with expected format

### Best Practices for New Checks

1. **Use feature flags** - Always make new checks optional via environment variables
2. **Handle errors gracefully** - Catch exceptions and log them
3. **Track metrics** - Increment error counters on failures
4. **Log appropriately** - Use logger.info/warning/error
5. **Set severity correctly** - HIGH for immediate action, MEDIUM for review
6. **Provide context** - Include resource IDs, account info, timestamps
7. **Avoid rate limits** - Use pagination, respect API limits
8. **Test thoroughly** - Verify with real AWS resources
9. **Document changes** - Update README with new capabilities
10. **Update IAM policies** - Add minimal required permissions

## License

MIT License - See LICENSE file

---

**Version**: 2.1.0 (Streamlined)  
**Status**: Production Ready  
**Setup Time**: 5-10 minutes  
**Monthly Cost**: <$1
