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

## Deployment Options

This project supports two deployment methods:
- **CloudFormation**: AWS-native deployment via a single template
- **Terraform**: Full infrastructure as code module with examples

---

## Option 1: CloudFormation (AWS Native)

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

## Option 2: Terraform (Infrastructure as Code)

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
make package
# Or manually:
# pip install -r requirements-lambda.txt -t .
# zip -r function.zip security_notifier/ boto3/ botocore/ requests/ urllib3/ certifi/ charset_normalizer/ idna/ dateutil/ jmespath/ s3transfer/

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
- **EnableGuardDuty** - Enable GuardDuty integration (`true`/`false`, default: `false`)
- **EnableSecurityHub** - Enable Security Hub integration (`true`/`false`, default: `false`)
- **EnableIAM** - Enable IAM security checks (`true`/`false`, default: `true`)
- **EnableCloudTrail** - Enable CloudTrail checks (`true`/`false`, default: `true`)
- **EnableS3** - Enable S3 security checks (`true`/`false`, default: `true`)
- **EnableEC2** - Enable EC2 security checks (`true`/`false`, default: `true`)
- **EnableConfig** - Enable AWS Config integration (`true`/`false`, default: `false`)
- **EnableECS** - Enable ECS monitoring (`true`/`false`, default: `true`)
- **EnableEKS** - Enable EKS monitoring (`true`/`false`, default: `true`)

### Environment Variables
Configure Lambda function behavior:
- `SLACK_WEBHOOK_URL` - Slack webhook (required)
- `ACCOUNT_NAME` - Account display name
- `WHITELIST_RESOURCES` - ARN patterns to ignore (comma-separated)
- `CRITICAL_EVENTS` - Critical event names (comma-separated)
- `ENABLE_GUARDDUTY` - Enable GuardDuty checks (default: true)
- `ENABLE_SECURITYHUB` - Enable Security Hub checks (default: true)
- `ENABLE_IAM` - Enable IAM checks (default: true)
- `ENABLE_CLOUDTRAIL` - Enable CloudTrail checks (default: true)
- `ENABLE_S3` - Enable S3 checks (default: true)
- `ENABLE_EC2` - Enable EC2 checks (default: true)
- `ENABLE_CONFIG` - Enable AWS Config checks (default: true)
- `ENABLE_ECS` - Enable ECS checks (default: true)
- `ENABLE_EKS` - Enable EKS checks (default: true)
- `MAX_RETRIES` - Max retry attempts (default: 3)
- `RETRY_DELAY_SECONDS` - Retry delay (default: 2)
- `RATE_LIMIT_PER_MINUTE` - Message rate limit (default: 30)
- `MAX_SLACK_MESSAGE_LENGTH` - Max message size (default: 3000)

## Security Checks

The system performs comprehensive security checks across multiple AWS services. Each check can be individually enabled or disabled.

### IAM Security Checks (ENABLE_IAM)
- Users with console access but no MFA enabled
- Overly permissive policies (admin access with * on *)
- Access keys older than 90 days
- Root account usage detection

### CloudTrail Security Checks (ENABLE_CLOUDTRAIL)
- No CloudTrail trails configured
- CloudTrail not logging
- Single-region trails (should be multi-region)
- Log file validation not enabled

### S3 Security Checks (ENABLE_S3)
- Buckets without public access block enabled
- Buckets without default encryption
- Buckets without versioning enabled
- Buckets without access logging

### EC2 Security Checks (ENABLE_EC2)
- Security groups allowing SSH (22) from 0.0.0.0/0
- Security groups allowing RDP (3389) from 0.0.0.0/0
- Security groups allowing all traffic from 0.0.0.0/0
- EC2 instances not requiring IMDSv2
- Unencrypted EBS volumes

### GuardDuty (ENABLE_GUARDDUTY)
- High-severity threat findings (severity >= 4)
- Active security threats detected

### Security Hub (ENABLE_SECURITYHUB)
- Critical and high-severity findings
- Security standard violations

### AWS Config (ENABLE_CONFIG)
- AWS Config not enabled or not recording
- Non-compliant config rules
- Missing delivery channels

### ECS Security Checks (ENABLE_ECS)
- Containers with hardcoded secrets in environment variables
- Containers running in privileged mode
- Containers running as root user
- Services with public IP assignment enabled

### EKS Security Checks (ENABLE_EKS)
- Clusters with public endpoint access from 0.0.0.0/0
- Clusters without private endpoint access
- Clusters without control plane logging
- Clusters without secrets encryption
- Clusters running outdated Kubernetes versions

### Event-Based Monitoring
Real-time CloudTrail event monitoring for:
- IAM user/role/policy changes
- S3 bucket policy modifications
- EC2 security group changes
- CloudTrail configuration changes
- Config rule modifications
- KMS key operations
- Secrets Manager operations
- ECS/EKS resource changes

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

### Component Flow

1. **EventBridge** captures CloudTrail events from monitored AWS services
2. **SQS Queue** buffers events for processing (with DLQ for failures)
3. **Lambda Function** processes events and runs security checks
4. **Slack Notifier** sends formatted alerts with retry logic
5. **CloudWatch** logs all activity and metrics

## Extending with Custom Checks

The system uses a modular, registry-based architecture that makes it easy to add new security checks without modifying core code.

### Quick Example

1. Create a new check module in `src/security_notifier/checks/`:

```python
"""RDS security check."""
import logging

logger = logging.getLogger(__name__)

def run(config, clients):
    """Check RDS security issues."""
    events = []
    rds = clients.get("rds")
    
    instances = rds.describe_db_instances(MaxRecords=100)
    for db in instances.get("DBInstances", []):
        if db.get("PubliclyAccessible"):
            events.append({
                "severity": "CRITICAL",
                "description": f"RDS {db['DBInstanceIdentifier']} is publicly accessible"
            })
    
    return events
```

2. Register it in `src/security_notifier/checks/__init__.py`:

```python
from . import rds

REGISTRY = [
    # ... existing checks ...
    ("enable_rds", "RDS Security", rds),
]
```

3. Add config flag in `src/security_notifier/config.py`:

```python
self.enable_rds = os.getenv("ENABLE_RDS", "true").lower() == "true"
```

That's it! The handler will automatically discover and run your check.

### Complete Developer Guide

For a comprehensive guide on adding new security checks, including:
- Module structure and best practices
- CloudFormation and Terraform integration
- Testing strategies
- Real-world examples

See: **[docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)**

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
make package
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

The system uses a modular, registry-based architecture that makes adding new checks simple and clean.

### Quick Example

See the "Extending with Custom Checks" section above for a quick example, or refer to the comprehensive developer guide.

### Complete Guide

For detailed instructions on adding new security checks, including:
- Module structure and best practices
- Step-by-step implementation guide
- CloudFormation and Terraform integration
- Testing strategies
- Multiple real-world examples

**See:** [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)

## License

MIT License - See LICENSE file

---

**Version**: 3.0.0  
**Status**: Production Ready  
**Setup Time**: 5-10 minutes  
**Monthly Cost**: <$1
