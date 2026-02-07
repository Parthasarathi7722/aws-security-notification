# Quick Start Guide

Get up and running in 5 minutes.

## Step 1: Get Slack Webhook (2 min)
1. Go to https://api.slack.com/messaging/webhooks
2. Click "Create New Webhook"
3. Select your channel
4. Copy the URL (starts with `https://hooks.slack.com/`)

## Step 2: Create S3 Bucket (1 min)
```bash
aws s3 mb s3://my-security-notifications-$(date +%s)
# Note the bucket name for next step
```

## Step 3: Package & Upload (1 min)
```bash
# Package Lambda
make package

# Upload
aws s3 cp function.zip s3://YOUR_BUCKET_NAME/
```

## Step 4: Deploy (1 min)
```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name security-alerts \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    LambdaCodeBucket=YOUR_BUCKET_NAME \
    SlackWebhookUrl=YOUR_SLACK_WEBHOOK
```

## Step 5: Test (30 sec)
```bash
# Create a test user (triggers alert)
aws iam create-user --user-name test-alert-$(date +%s)

# Check Slack - you should see a notification

# Clean up
aws iam delete-user --user-name test-alert-*
```

## Done

Your security monitoring is now active. Check Slack for alerts.

## Next Steps

### View Logs
```bash
aws logs tail /aws/lambda/security-alerts-notification-lambda --follow
```

### Enable Optional Services
```bash
# Enable GuardDuty, Security Hub, Config
aws cloudformation update-stack \
  --stack-name security-alerts \
  --use-previous-template \
  --parameters \
    ParameterKey=EnableGuardDuty,ParameterValue=true \
    ParameterKey=EnableSecurityHub,ParameterValue=true \
    ParameterKey=EnableConfig,ParameterValue=true \
  --capabilities CAPABILITY_IAM
```

### Add Whitelisting
```bash
aws lambda update-function-configuration \
  --function-name security-alerts-notification-lambda \
  --environment Variables="{SLACK_WEBHOOK_URL=YOUR_URL,WHITELIST_RESOURCES=arn:aws:iam::*:role/ServiceRole*}"
```

### Set Critical Events
```bash
aws lambda update-function-configuration \
  --function-name security-alerts-notification-lambda \
  --environment Variables="{SLACK_WEBHOOK_URL=YOUR_URL,CRITICAL_EVENTS=CreateUser;DeleteUser;DeleteRole}"
```

## Troubleshooting

### Not getting alerts?
```bash
# Check Lambda logs
aws logs tail /aws/lambda/security-alerts-notification-lambda --follow

# Verify rule is enabled
aws events list-rules --name-prefix security-alerts

# Test manually
aws iam create-user --user-name test-user-$(date +%s)
```

### Need help?
- Check README.md for full documentation
- Review CloudWatch Logs for errors
- Verify Slack webhook URL
- Ensure Lambda has internet access

## Clean Up (If Needed)
```bash
# Delete stack
aws cloudformation delete-stack --stack-name security-alerts

# Delete S3 objects
aws s3 rm s3://YOUR_BUCKET_NAME/function.zip
```

---

**Setup Time**: 5 minutes  
**Cost**: <$1/month  
**Support**: See README.md

