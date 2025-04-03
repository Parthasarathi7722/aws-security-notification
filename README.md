# AWS Security Event Notification System

This project provides a comprehensive security event monitoring and notification system for AWS environments. It leverages AWS EventBridge, SQS, Lambda, and Slack to provide real-time notifications about security-related events and potential risks in your AWS environment.

## Features

### Core Security Monitoring
- Real-time monitoring of critical AWS events
- Integration with multiple AWS security services
- Configurable event filtering and whitelisting
- Aggregated notifications to reduce alert fatigue
- Critical event highlighting in Slack

### Optional Security Service Integration
- AWS GuardDuty integration for threat detection (optional)
- AWS Security Hub findings monitoring (optional)
- AWS Config compliance status tracking (optional)

### Container Security Monitoring
- ECS cluster security monitoring
  - Cluster status monitoring
  - Privileged container detection
  - Task definition security checks
- EKS cluster security monitoring
  - Cluster status monitoring
  - Logging configuration checks
  - Public access monitoring
  - Node group security

### Additional Security Monitoring
- MFA usage monitoring
- Root account activity detection
- Password-related activity monitoring
- Failed API call detection
- Resource policy changes tracking

### Supported Event Types
1. **IAM Events**
   - User creation/deletion
   - Role creation/deletion
   - Policy attachments/detachments
   - Console logins
   - MFA usage

2. **S3 Events**
   - Bucket policy changes
   - Object access patterns
   - Bucket configuration changes

3. **EC2 Events**
   - Security group changes
   - Network ACL modifications
   - Instance state changes

4. **CloudTrail Events**
   - Logging configuration changes
   - Trail creation/deletion
   - Log file delivery status

5. **AWS Config Events**
   - Configuration recorder changes
   - Rule creation/deletion
   - Compliance status changes

6. **Container Events**
   - ECS cluster changes
   - Task definition updates
   - Service modifications
   - EKS cluster changes
   - Node group updates
   - Fargate profile changes

7. **Additional Services**
   - KMS key operations
   - Secrets Manager changes
   - RDS instance modifications
   - DynamoDB table changes
   - Redshift cluster operations
   - ElastiCache modifications
   - Elasticsearch domain changes
   - Workspaces operations
   - Organizations changes

## Architecture

1. **Event Sources**
   - AWS EventBridge rules capture security events
   - Optional GuardDuty findings
   - Optional Security Hub findings
   - Optional AWS Config compliance status
   - Container security events

2. **Processing Layer**
   - SQS queue for event buffering
   - Dead Letter Queue for failed processing
   - Lambda function for event processing

3. **Notification Layer**
   - Slack integration for real-time alerts
   - Formatted messages with security risk indicators
   - Critical event highlighting

## Deployment

### Option 1: Using CloudFormation (Recommended)

1. **Prerequisites**
   - AWS CLI configured with appropriate credentials
   - Slack webhook URL
   - S3 bucket for Lambda code
  
2. **Download and Prepare the Project**

Download the Repository**
1. Navigate to the [GitHub repository](https://github.com/psd/SecOps_lambda_package).
2. Download the project as a ZIP file and extract it locally.

Install Dependencies (Optional)**
1. The project includes required dependencies (`certifi`, `requests`, `urllib3`, etc.). If any dependency is missing or needs updating, use:
   ```bash
   pip install -r requirements.txt -t .
   ```

3. **Deploy the Stack**
   ```bash
   # Package the Lambda function
   zip -r function.zip SecOps_notification.py certifi charset_normalizer idna requests urllib3

   # Upload to S3
   aws s3 cp function.zip s3://your-bucket/function.zip

   # Deploy the CloudFormation stack
   aws cloudformation deploy \
     --template-file template.yaml \
     --stack-name security-notification-stack \
     --capabilities CAPABILITY_IAM \
     --parameter-overrides \
       SlackWebhookUrl=your-slack-webhook-url \
       AccountName=your-account-name \
       WhitelistResources=arn:aws:iam::123456789012:role/WhitelistedRole \
       EnableGuardDuty=false \
       EnableSecurityHub=false \
       EnableConfig=false \
       EnableECS=true \
       EnableEKS=true
   ```

### Option 2: Manual Deployment

1. **Create Required Resources**
   - Create an SQS queue
   - Create a Lambda function
   - Set up EventBridge rules
   - Configure Slack webhook

2. **Configure Environment Variables**
   ```bash
   SLACK_WEBHOOK_URL=your-slack-webhook-url
   ACCOUNT_NAME=your-account-name
   WHITELIST_RESOURCES=arn:aws:iam::123456789012:role/WhitelistedRole
   CRITICAL_EVENTS=CreateUser,DeleteUser,CreateRole,DeleteRole
   ENABLE_GUARDDUTY=false
   ENABLE_SECURITYHUB=false
   ENABLE_CONFIG=false
   ENABLE_ECS=true
   ENABLE_EKS=true
   ```

## Customization

### Event Filtering

1. **Whitelisting Resources**
   - Add ARNs to the `WHITELIST_RESOURCES` environment variable
   - Supports wildcards (e.g., `arn:aws:iam::*:role/AdminRole`)

2. **Critical Events**
   - Configure `CRITICAL_EVENTS` environment variable
   - Events listed will be highlighted in Slack notifications

3. **Service Integration**
   - Toggle service integration using environment variables:
     - `ENABLE_GUARDDUTY`: Enable/disable GuardDuty integration
     - `ENABLE_SECURITYHUB`: Enable/disable Security Hub integration
     - `ENABLE_CONFIG`: Enable/disable AWS Config integration
     - `ENABLE_ECS`: Enable/disable ECS security monitoring
     - `ENABLE_EKS`: Enable/disable EKS security monitoring

### Container Security Monitoring

1. **ECS Security Checks**
   - Cluster status monitoring
   - Privileged container detection
   - Task definition security
   - Service configuration changes

2. **EKS Security Checks**
   - Cluster status monitoring
   - Logging configuration
   - Public access settings
   - Node group security
   - Fargate profile changes

### Removing Events

To remove specific events from monitoring:

1. **Using CloudFormation**
   - Update the `SecurityEventRule` in `template.yaml`
   - Remove unwanted events from the `eventName` list
   - Deploy the updated stack

2. **Manual Configuration**
   - Update EventBridge rules in AWS Console
   - Remove unwanted event patterns
   - Update Lambda function code if needed

## Security Considerations

1. **IAM Permissions**
   - Lambda function requires minimal permissions
   - Follow principle of least privilege
   - Regular permission audit recommended

2. **Data Protection**
   - Slack webhook URL stored securely
   - Sensitive data not logged
   - Event data retention configurable

3. **Monitoring Best Practices**
   - Regular review of whitelisted resources
   - Periodic assessment of critical events
   - Monitor Lambda function performance
   - Regular container security audits

## Troubleshooting

1. **Missing Notifications**
   - Verify Slack webhook URL
   - Check CloudWatch Logs
   - Validate EventBridge rules

2. **Performance Issues**
   - Monitor Lambda execution time
   - Check SQS queue metrics
   - Review CloudWatch alarms

3. **Integration Problems**
   - Verify service permissions
   - Check service status
   - Review error logs

4. **Container Monitoring Issues**
   - Verify ECS/EKS permissions
   - Check cluster status
   - Review container logs


---

## **Repository Structure**
- `SecOps_notification.py`: The primary Lambda function script responsible for processing events and sending notifications to Slack.
- `bin/`: Folder containing compiled or auxiliary executables (if applicable).
- `certifi`, `charset_normalizer`, `idna`, `requests`, `urllib3`: Dependencies required by the script, included in the repository for deployment.
- `.gitattributes`: Configuration for repository attributes.
- `README.md`: This documentation file.

---

## **Project Architecture**
1. **AWS EventBridge:**
   - Captures specific AWS events based on pre-defined rules.
2. **SQS:**
   - Serves as a buffer to decouple EventBridge and Lambda.
3. **AWS Lambda:**
   - Processes events from SQS, formats the message, and sends it to Slack.
4. **Slack Webhook:**
   - Receives notifications formatted by Lambda.

---

## **Setup Instructions**

### **1. Prerequisites**
- **AWS Account**: Ensure you have an active AWS account.
- **Slack Webhook URL**:
  - Create an [Incoming Webhook](https://api.slack.com/messaging/webhooks) in Slack and note the URL.
- **AWS CLI**:
  - Install and configure the AWS CLI for your account.

---

### **2. Download and Deploy the Project**

#### **Step 1: Download the Repository**
1. Navigate to the [GitHub repository](https://github.com/psd/SecOps_lambda_package).
2. Download the project as a ZIP file and extract it locally.

#### **Step 2: Install Dependencies (Optional)**
1. The project includes required dependencies (`certifi`, `requests`, `urllib3`, etc.). If any dependency is missing or needs updating, use:
   ```bash
   pip install -r requirements.txt -t .
   ```

#### **Step 3: Package the Project**
1. Zip the project files, including dependencies:
   ```bash
   zip -r lambda_function.zip SecOps_notification.py certifi charset_normalizer idna requests urllib3
   ```

#### **Step 4: Deploy the Lambda Function**
1. Create a Lambda function:
   ```bash
   aws lambda create-function \
     --function-name EventNotificationsLambda \
     --runtime python3.9 \
     --role <IAM-Role-ARN> \
     --handler SecOps_notification.lambda_handler \
     --timeout 15 \
     --memory-size 128 \
     --zip-file fileb://lambda_function.zip
   ```
2. Add environment variables for the Slack Webhook and account name:
   ```bash
   aws lambda update-function-configuration \
     --function-name EventNotificationsLambda \
     --environment Variables={SLACK_WEBHOOK_URL=<Webhook-URL>,ACCOUNT_NAME=<Account-Name>,WHITELIST_RESOURCES=<comma-separated-ARNs>}
   ```

#### **Step 5: Configure AWS Resources**
1. **SQS Queue**:
   - Navigate to the SQS console and create a standard queue.
   - Note the ARN for use in EventBridge and Lambda configurations.
2. **EventBridge Rules**:
   - Set up rules to capture events matching your security and operational needs.
   - Target the SQS queue created above.

#### **Step 6: Add Lambda Trigger**
1. Attach the SQS queue as a trigger to the Lambda function in the AWS Lambda console.

---

## **IAM Permissions**
Ensure the following permissions are added to your Lambda execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ],
      "Resource": "<SQS-Queue-ARN>"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "s3:GetBucketPolicy",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## **Environment Variables**
- `SLACK_WEBHOOK_URL`: The Slack webhook URL to send alerts to a specific channel.
- `ACCOUNT_NAME`: A label to identify the AWS account in the alert message.
- `WHITELIST_RESOURCES`: A comma-separated list of ARNs or patterns for resources to exclude from notifications.

---

## **Supported Alerts**
### **Key Features**
- **Whitelisting**: Skips notifications for whitelisted ARNs defined in environment variables.
- **Aggregation**: Groups similar events into a single Slack message.
- **Error Handling**: Catches and logs exceptions without breaking the workflow.

### **Alert Types**
- **Security Group Changes**: Tracks ingress/egress modifications.
- **Unauthorized API Calls**: Detects API calls with `AccessDenied` responses.
- **IAM Events**:
  - Console login attempts (with/without MFA).
  - Changes to IAM roles, users, or policies.
- **S3 Bucket Changes**:
  - Bucket policy updates.
  - Object creation or deletion.
- **CloudTrail Configuration Changes**:
  - Start/stop logging.
  - Deletion or updates to trails.
- **Root Account Usage**: Tracks actions performed with the root account.

---

## **Slack Notification Format**
Example:
```plaintext
*Alert Details - Dev (XXXXXXXXXXXXX)*
* **Event Name:** ConsoleLogin
* **Action Result:** Action Allowed
* **Event Source:** signin.amazonaws.com
* **Attacker:** 106.71.200.69
* **Target Hostname:** us-west-2.signin.aws.amazon.com
* **Username:** AWSReservedSSO_DevAccess
* **User Type:** AssumedRole
* **Zone:** us-west-2
* **Principal ID:** AROAUXXXXXXXA7JD4KO33I:loki@company.com
* **MFA Authenticated:** false
* **ARN:** arn:aws:sts::XXXXXXXXXXXXXXXXX:assumed-role/AWSReservedSSO_DevOpsAccess/loki@company.com
* **User-Agent:** Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/132.0.0.0 Safari/537.36
*Additional Event Details:*
```json
{
  "requestParameters": {}
}
```

---

## **Troubleshooting**
1. **Slack Messages Not Received**:
   - Verify the Slack Webhook URL.
   - Check the Lambda CloudWatch logs for errors.

2. **SQS Queue Not Triggering Lambda**:
   - Confirm the SQS trigger is attached to the Lambda function.
   - Check for IAM permissions issues.

3. **Missing Notifications**:
   - Ensure EventBridge rules match the intended events.
   - Test events using the AWS CLI or console.


## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.
---

