# Basic Example

Deploy with minimal configuration.

## Usage

```bash
# Create terraform.tfvars
echo 'slack_webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"' > terraform.tfvars

# Deploy
terraform init
terraform plan
terraform apply
```

## What's Deployed

- Lambda function with default settings
- SQS queue for event buffering
- EventBridge rule for security events
- CloudWatch Logs with 30-day retention
- IAM role with minimal permissions

## Outputs

- `lambda_function_name`: Use for testing
- `cloudwatch_log_group`: Use for monitoring

## Testing

```bash
# Get function name
FUNCTION_NAME=$(terraform output -raw lambda_function_name)

# Test invocation
aws lambda invoke --function-name $FUNCTION_NAME --payload '{}' response.json

# View logs
LOG_GROUP=$(terraform output -raw cloudwatch_log_group)
aws logs tail $LOG_GROUP --follow
```

