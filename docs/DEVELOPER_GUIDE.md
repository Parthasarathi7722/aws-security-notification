# Developer Guide: Adding New Security Checks

This guide explains how to add new security checks to the AWS Security Notification System.

## Table of Contents

1. [Overview](#overview)
2. [Check Module Structure](#check-module-structure)
3. [Step-by-Step Guide](#step-by-step-guide)
4. [Best Practices](#best-practices)
5. [Testing](#testing)
6. [Examples](#examples)

---

## Overview

The security notification system uses a **registry-based architecture** where security checks are modular, pluggable components. Each check:

- Is a separate Python module in `src/security_notifier/checks/`
- Has a standardized `run(config, clients)` function
- Returns a list of findings with severity and description
- Can be enabled/disabled via environment variables

### Architecture

```
┌─────────────────┐
│  Lambda Handler │
│   (handler.py)  │
└────────┬────────┘
         │
         ├──> Registry Loop
         │    (checks/__init__.py)
         │
         ├──> Check Module 1 (guardduty.py)
         ├──> Check Module 2 (iam.py)
         ├──> Check Module 3 (s3.py)
         └──> Check Module N (custom.py)
              │
              ├──> AWS API Calls
              └──> Return Findings
```

---

## Check Module Structure

Every check module must follow this structure:

```python
"""Description of what this check does."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Check description.

    Args:
        config: Configuration object with settings and feature flags
        clients: ClientFactory instance for getting AWS service clients

    Returns:
        List of dicts with keys:
        - severity: str ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        - description: str (human-readable finding description)
    """
    events = []
    try:
        # Get AWS service client
        service_client = clients.get("service_name")

        # Perform checks
        # ... your logic here ...

        # Add findings
        if condition:
            events.append({
                "severity": "HIGH",
                "description": "Issue description with details",
            })

    except ClientError as e:
        # Handle AWS API errors gracefully
        logger.warning(f"Check error: {e}")
    except Exception as e:
        # Catch all other errors
        logger.error(f"Check error: {e}")

    return events
```

---

## Step-by-Step Guide

### Step 1: Create the Check Module

Create a new file in `src/security_notifier/checks/` (e.g., `lambda_check.py`):

```python
"""AWS Lambda security check."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get Lambda security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        lambda_client = clients.get("lambda")

        # List Lambda functions
        functions = lambda_client.list_functions(MaxItems=100)

        for func in functions.get("Functions", []):
            func_name = func.get("FunctionName")

            # Check 1: Public function URLs
            try:
                url_config = lambda_client.get_function_url_config(
                    FunctionName=func_name
                )
                auth_type = url_config.get("AuthType")
                if auth_type == "NONE":
                    events.append({
                        "severity": "HIGH",
                        "description": f"Lambda function {func_name} has public URL with no authentication",
                    })
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    logger.debug(f"Error checking function URL: {e}")

            # Check 2: No VPC configuration
            if not func.get("VpcConfig") or not func.get("VpcConfig", {}).get("VpcId"):
                events.append({
                    "severity": "MEDIUM",
                    "description": f"Lambda function {func_name} is not in a VPC",
                })

            # Check 3: Old runtime versions
            runtime = func.get("Runtime", "")
            if any(old in runtime for old in ["python3.6", "python3.7", "nodejs12", "nodejs14"]):
                events.append({
                    "severity": "MEDIUM",
                    "description": f"Lambda function {func_name} uses deprecated runtime {runtime}",
                })

    except Exception as e:
        logger.error(f"Lambda check error: {e}")

    return events
```

### Step 2: Register the Check

Edit `src/security_notifier/checks/__init__.py`:

```python
"""Security check registry."""
from . import guardduty, securityhub, iam, cloudtrail, s3, ec2, ecs, eks, config
from . import lambda_check  # Import your new check

# (config_flag_attr, label, module)
REGISTRY = [
    ("enable_guardduty", "GuardDuty", guardduty),
    ("enable_securityhub", "Security Hub", securityhub),
    # ... existing checks ...
    ("enable_lambda", "Lambda Security", lambda_check),  # Add your check
]
```

### Step 3: Add Configuration Flag

Edit `src/security_notifier/config.py`:

```python
class Config:
    def __init__(self):
        # ... existing code ...

        # Add your feature flag
        self.enable_lambda = os.getenv("ENABLE_LAMBDA", "true").lower() == "true"
```

### Step 4: Update CloudFormation Template

Add to `template.yaml`:

#### 4a. Add Parameter

```yaml
Parameters:
  # ... existing parameters ...

  EnableLambda:
    Type: String
    Description: Enable Lambda security monitoring (true/false)
    Default: 'true'
    AllowedValues:
      - 'true'
      - 'false'
```

#### 4b. Add to Parameter Groups (Metadata section)

```yaml
Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups:
      - Label:
          default: "Optional Services (Enable as needed)"
        Parameters:
          # ... existing parameters ...
          - EnableLambda
```

#### 4c. Add to Lambda Environment Variables

```yaml
Resources:
  NotificationLambda:
    Properties:
      Environment:
        Variables:
          # ... existing variables ...
          ENABLE_LAMBDA: !Ref EnableLambda
```

#### 4d. Add IAM Permissions

```yaml
Resources:
  NotificationLambdaRole:
    Properties:
      Policies:
        - PolicyName: NotificationLambdaPolicy
          PolicyDocument:
            Statement:
              # ... existing statements ...
              - Effect: Allow
                Action:
                  - lambda:ListFunctions
                  - lambda:GetFunction
                  - lambda:GetFunctionUrlConfig
                Resource: '*'
```

### Step 5: Update Terraform Module

Edit `terraform/main.tf`:

#### 5a. Add Variable

```hcl
variable "enable_lambda" {
  description = "Enable Lambda security monitoring"
  type        = bool
  default     = true
}
```

#### 5b. Add to Lambda Environment

```hcl
resource "aws_lambda_function" "notifier" {
  environment {
    variables = {
      # ... existing variables ...
      ENABLE_LAMBDA = var.enable_lambda
    }
  }
}
```

#### 5c. Add IAM Permissions

```hcl
data "aws_iam_policy_document" "lambda_policy" {
  # ... existing statements ...

  statement {
    effect = "Allow"
    actions = [
      "lambda:ListFunctions",
      "lambda:GetFunction",
      "lambda:GetFunctionUrlConfig",
    ]
    resources = ["*"]
  }
}
```

### Step 6: Add Tests

Create tests in `tests/test_checks.py`:

```python
from security_notifier.checks import lambda_check

class TestLambda:
    def test_no_functions(self):
        clients = _mock_clients({
            "lambda": {"list_functions": {"Functions": []}}
        })
        assert lambda_check.run(_config(), clients) == []

    def test_public_function_url(self):
        lambda_mock = MagicMock()
        lambda_mock.list_functions.return_value = {
            "Functions": [{"FunctionName": "test-func"}]
        }
        lambda_mock.get_function_url_config.return_value = {
            "AuthType": "NONE"
        }

        clients = MagicMock()
        clients.get = lambda name: lambda_mock if name == "lambda" else MagicMock()

        result = lambda_check.run(_config(), clients)
        assert any("public URL" in e["description"] for e in result)
```

### Step 7: Update Documentation

Update `README.md` to document the new check:

```markdown
## Security Checks

### AWS Lambda
- Public function URLs without authentication
- Functions not in VPC
- Deprecated runtime versions
- ... (list all checks)
```

---

## Best Practices

### 1. Error Handling

Always handle AWS API errors gracefully:

```python
try:
    response = client.some_api_call()
except ClientError as e:
    error_code = e.response.get("Error", {}).get("Code")
    if error_code == "AccessDenied":
        logger.warning(f"No permission for API call")
        return events
    elif error_code == "ResourceNotFoundException":
        # Expected error, continue
        pass
    else:
        logger.error(f"Unexpected error: {e}")
except Exception as e:
    logger.error(f"Check error: {e}")
```

### 2. Performance

Limit API calls to avoid timeouts:

```python
# Use pagination limits
functions = lambda_client.list_functions(MaxItems=100)

# Don't iterate over thousands of resources
for resource in resources[:100]:  # Limit to first 100
    # ... check logic ...
```

### 3. Severity Levels

Use consistent severity levels:

- **CRITICAL**: Immediate security risk (public access, unencrypted sensitive data)
- **HIGH**: Significant security gap (no MFA, overly permissive policies)
- **MEDIUM**: Security best practice violation (no logging, outdated versions)
- **LOW**: Minor configuration issue (missing tags, optional features)

### 4. Clear Descriptions

Write actionable, specific descriptions:

```python
# Good
"Lambda function prod-api has public URL with no authentication"

# Bad
"Function has security issue"
```

### 5. Logging

Use appropriate log levels:

```python
logger.debug()   # Detailed diagnostic info
logger.info()    # General information
logger.warning() # Expected but notable conditions
logger.error()   # Errors that need attention
```

---

## Testing

### Unit Tests

Run unit tests:

```bash
make test
```

### Local Testing

Test your check locally:

```python
# test_local.py
import boto3
from security_notifier.config import Config
from security_notifier.clients import ClientFactory
from security_notifier.checks import lambda_check

config = Config()
clients = ClientFactory()

results = lambda_check.run(config, clients)
for result in results:
    print(f"[{result['severity']}] {result['description']}")
```

### Integration Testing

Deploy to AWS and trigger:

```bash
# Deploy
make deploy

# Test by creating a resource that should trigger the check
aws lambda create-function ...

# Check CloudWatch Logs
aws logs tail /aws/lambda/security-notifications --follow
```

---

## Examples

### Example 1: Simple Resource Check

```python
"""RDS security check."""
import logging

logger = logging.getLogger(__name__)


def run(config, clients):
    events = []
    try:
        rds = clients.get("rds")
        instances = rds.describe_db_instances(MaxRecords=100)

        for db in instances.get("DBInstances", []):
            db_id = db.get("DBInstanceIdentifier")

            # Check public accessibility
            if db.get("PubliclyAccessible"):
                events.append({
                    "severity": "CRITICAL",
                    "description": f"RDS instance {db_id} is publicly accessible",
                })

            # Check encryption
            if not db.get("StorageEncrypted"):
                events.append({
                    "severity": "HIGH",
                    "description": f"RDS instance {db_id} is not encrypted",
                })

    except Exception as e:
        logger.error(f"RDS check error: {e}")

    return events
```

### Example 2: Multi-Resource Check

```python
"""VPC security check."""
import logging

logger = logging.getLogger(__name__)


def run(config, clients):
    events = []
    try:
        ec2 = clients.get("ec2")

        # Check default VPC usage
        vpcs = ec2.describe_vpcs(MaxResults=100)
        for vpc in vpcs.get("Vpcs", []):
            if vpc.get("IsDefault"):
                # Check if default VPC has resources
                subnets = ec2.describe_subnets(
                    Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}]
                )
                instances = ec2.describe_instances(
                    Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}]
                )

                if instances.get("Reservations"):
                    events.append({
                        "severity": "MEDIUM",
                        "description": f"Instances running in default VPC {vpc['VpcId']}",
                    })

        # Check flow logs
        for vpc in vpcs.get("Vpcs", []):
            vpc_id = vpc.get("VpcId")
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )

            if not flow_logs.get("FlowLogs"):
                events.append({
                    "severity": "MEDIUM",
                    "description": f"VPC {vpc_id} does not have flow logs enabled",
                })

    except Exception as e:
        logger.error(f"VPC check error: {e}")

    return events
```

### Example 3: Complex Logic Check

```python
"""Secrets Manager security check."""
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


def run(config, clients):
    events = []
    try:
        sm = clients.get("secretsmanager")

        # List secrets
        secrets = sm.list_secrets(MaxResults=100)

        for secret in secrets.get("SecretList", []):
            secret_name = secret.get("Name")
            secret_arn = secret.get("ARN")

            # Check rotation
            rotation_enabled = secret.get("RotationEnabled", False)
            if not rotation_enabled:
                events.append({
                    "severity": "MEDIUM",
                    "description": f"Secret {secret_name} does not have automatic rotation enabled",
                })

            # Check age
            last_changed = secret.get("LastChangedDate")
            if last_changed:
                age = datetime.now(timezone.utc) - last_changed
                if age > timedelta(days=90):
                    events.append({
                        "severity": "HIGH",
                        "description": f"Secret {secret_name} has not been rotated in {age.days} days",
                    })

            # Check resource policy
            try:
                policy = sm.get_resource_policy(SecretId=secret_arn)
                # Parse and check for overly permissive policies
                # ... complex policy analysis ...
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Secrets Manager check error: {e}")

    return events
```

---

## Summary

To add a new security check:

1. ✅ Create check module in `src/security_notifier/checks/`
2. ✅ Register in `checks/__init__.py`
3. ✅ Add config flag in `config.py`
4. ✅ Update CloudFormation template (`template.yaml`)
5. ✅ Update Terraform module (`terraform/main.tf`)
6. ✅ Write tests in `tests/test_checks.py`
7. ✅ Update documentation in `README.md`
8. ✅ Test locally and deploy

The modular architecture makes it easy to add, remove, or modify checks without affecting the core system!

