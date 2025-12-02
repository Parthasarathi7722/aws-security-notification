# Advanced Example

Production-ready deployment with all features enabled.

## Features

- All optional services enabled (GuardDuty, Security Hub, Config, ECS, EKS)
- Custom Lambda configuration (512MB memory, 90s timeout)
- Resource whitelisting
- Critical event tagging
- CloudWatch alarms
- Production tags

## Usage

```bash
# Create terraform.tfvars
cat > terraform.tfvars << EOF
slack_webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
EOF

# Deploy
terraform init
terraform plan
terraform apply
```

## What's Deployed

- Lambda function with production settings
- SQS queue with DLQ
- EventBridge rule capturing all security events
- CloudWatch Logs (30-day retention)
- CloudWatch Alarms (errors, DLQ messages)
- IAM role with permissions for all services
- Comprehensive tagging

## Configuration

This example includes:

- **Memory**: 512MB (vs 256MB default)
- **Timeout**: 90s (vs 60s default)
- **Services**: All enabled
- **Whitelisting**: ServiceRole patterns
- **Critical Events**: User/Role/Bucket operations
- **Alarms**: Enabled for monitoring

## Monitoring

After deployment, use the provided commands:

```bash
# View all outputs
terraform output all_outputs

# Get monitoring commands
terraform output -raw monitoring_commands
```

## Testing

```bash
# Trigger a test event
aws iam create-user --user-name test-security-alert-$(date +%s)

# Check Slack for notification
# Check CloudWatch Logs
terraform output -raw monitoring_commands | grep "aws logs tail" | sh
```

## Cost Estimate

Monthly cost (with all services enabled):
- Lambda: ~$0.40 (higher memory, more invocations)
- SQS: ~$0.05
- CloudWatch Logs: ~$0.50
- CloudWatch Alarms: ~$0.20

**Total: ~$1.15/month**

## Customization

Edit variables in `main.tf`:

- Change `function_name` for custom naming
- Adjust `whitelist_resources` for your environment
- Modify `critical_events` for your needs
- Update `tags` for your organization

## Production Checklist

- [ ] Update Slack webhook URL
- [ ] Review whitelisted resources
- [ ] Verify critical events list
- [ ] Set appropriate tags
- [ ] Enable alarms
- [ ] Test notifications
- [ ] Document in runbooks

