# AWS Security Notification System

Real-time Slack notifications for AWS security events with retry logic, rate limiting, and CloudWatch metrics.

![AWS](https://img.shields.io/badge/AWS-CloudFormation-orange?logo=amazon-aws)
![Python](https://img.shields.io/badge/python-3.11-blue?logo=python)
![Terraform](https://img.shields.io/badge/Terraform-1.6+-purple?logo=terraform)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Real-time Alerts** - Instant Slack notifications for security events
- **Core Security Checks** - GuardDuty, Security Hub, IAM, CloudTrail
- **Smart Retry Logic** - Exponential backoff for failed deliveries
- **Rate Limiting** - Prevents Slack API throttling (30 msg/min)
- **Event Filtering** - Whitelist support with wildcard patterns
- **Minimal Dependencies** - Only boto3 and requests
- **Clean Architecture** - Lean, maintainable, easy to extend

## Architecture

```
AWS Services -> EventBridge -> SQS Queue -> Lambda -> Slack
```

```
src/security_notifier/
  __init__.py           # Lambda handler exposure
  config.py             # Configuration from environment
  clients.py            # Lazy boto3 ClientFactory
  slack.py              # SlackNotifier with retry & rate limiting
  formatter.py          # Event message formatting
  handler.py            # Lambda handler
  checks/               # Core security checks
    guardduty.py        # GuardDuty findings
    securityhub.py      # Security Hub findings
    iam.py              # IAM security events
    cloudtrail.py       # CloudTrail API calls
```

## Quick Start

### Option 1: CloudFormation

```bash
git clone https://github.com/Parthasarathi7722/aws-security-notification.git
cd aws-security-notification
make package
aws s3 cp function.zip s3://YOUR_BUCKET/
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name security-notifications \
  --parameter-overrides \
    LambdaCodeBucket=YOUR_BUCKET \
    SlackWebhookUrl=YOUR_WEBHOOK_URL \
  --capabilities CAPABILITY_IAM
```

### Option 2: Terraform

```hcl
module "security_notifications" {
  source = "github.com/Parthasarathi7722/aws-security-notification//terraform"

  slack_webhook_url   = var.slack_webhook_url
  enable_guardduty    = true
  enable_security_hub = true
}
```

```bash
cd aws-security-notification && make package
cd terraform && terraform init && terraform apply
```

### Option 3: Python Package

```bash
pip install .
```

```python
from aws_security_notification import lambda_handler
resp = lambda_handler({"Records": []}, context=None)
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SLACK_WEBHOOK_URL` | Slack webhook (required) | - |
| `ACCOUNT_NAME` | Account display name | `AWS Account` |
| `WHITELIST_RESOURCES` | ARN patterns to ignore (comma-separated) | `""` |
| `CRITICAL_EVENTS` | Critical event names (comma-separated) | `""` |
| `ENABLE_GUARDDUTY` | Enable GuardDuty | `false` |
| `ENABLE_SECURITYHUB` | Enable Security Hub | `false` |
| `ENABLE_CONFIG` | Enable AWS Config | `false` |
| `ENABLE_ECS` | Enable ECS monitoring | `true` |
| `ENABLE_EKS` | Enable EKS monitoring | `true` |
| `ENABLE_RDS` | Enable RDS monitoring | `true` |
| `ENABLE_LAMBDA_CHECKS` | Enable Lambda checks | `true` |
| `ENABLE_IAM_CHECKS` | Enable IAM checks | `true` |
| `ENABLE_S3_CHECKS` | Enable S3 checks | `true` |
| `ENABLE_CLOUDTRAIL_CHECKS` | Enable CloudTrail checks | `true` |
| `ENABLE_KMS_CHECKS` | Enable KMS checks | `true` |
| `ENABLE_SECRETS_CHECKS` | Enable Secrets Manager checks | `true` |
| `MAX_RETRIES` | Max retry attempts | `3` |
| `RETRY_DELAY_SECONDS` | Retry delay | `2` |
| `RATE_LIMIT_PER_MINUTE` | Message rate limit | `30` |
| `MAX_SLACK_MESSAGE_LENGTH` | Max message size | `3000` |

## Adding New Security Checks

Create a new module in `src/security_notifier/checks/`:

```python
# src/security_notifier/checks/my_service.py
def run(config, clients):
    """Returns list of {"severity": str, "description": str}."""
    events = []
    svc = clients.get("my-service")
    # ... check logic ...
    return events
```

Register it in `src/security_notifier/checks/__init__.py`:

```python
from . import my_service
REGISTRY.append(("enable_my_service", "My Service", my_service))
```

Add the feature flag to `Config` in `config.py`, update IAM permissions in `template.yaml`/`terraform/main.tf`, and done.

## Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
make test

# Build deployment package
make package
```

## Deployment Guide and Examples

- Detailed steps: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- Terraform module: [terraform/README.md](terraform/README.md)
- Examples: `examples/basic` and `examples/advanced`

## Cost Estimate

For 10,000 events/month: **~$0.84/month** (EventBridge $0.10, SQS $0.04, Lambda $0.20, CloudWatch $0.50)

## License

MIT License - See LICENSE file

---

**Version**: 3.0.0
**Status**: Production Ready
**Setup Time**: 5-10 minutes
