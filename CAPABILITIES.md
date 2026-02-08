# AWS Security Notification System - Current Capabilities

## Overview

A comprehensive, production-ready AWS security monitoring system that sends real-time Slack notifications for security events and configuration issues across 9 AWS services.

**Version:** 3.0.0  
**Last Updated:** February 8, 2026

---

## Deployment Methods

The system can be deployed using two methods:

1. **CloudFormation** - AWS-native infrastructure deployment
2. **Terraform** - Infrastructure as Code deployment

Both methods support the same features and security checks.

---

## Security Checks Coverage

### 1. IAM Security (ENABLE_IAM)
**Status:** ✅ Enabled by default

- ✅ Users with console access but no MFA enabled
- ✅ Overly permissive policies (admin access with * on *)
- ✅ Access keys older than 90 days
- ✅ Root account usage detection
- ✅ Real-time IAM user/role/policy change monitoring

**Severity Levels:** HIGH, MEDIUM

---

### 2. CloudTrail Security (ENABLE_CLOUDTRAIL)
**Status:** ✅ Enabled by default

- ✅ No CloudTrail trails configured (CRITICAL)
- ✅ CloudTrail not logging (CRITICAL)
- ✅ Single-region trails detection (HIGH)
- ✅ Log file validation not enabled (HIGH)
- ✅ Real-time trail configuration change monitoring

**Severity Levels:** CRITICAL, HIGH

---

### 3. S3 Security (ENABLE_S3)
**Status:** ✅ Enabled by default

- ✅ Buckets without public access block enabled (HIGH)
- ✅ Buckets without default encryption (MEDIUM)
- ✅ Buckets without versioning enabled (MEDIUM)
- ✅ Buckets without access logging (LOW)
- ✅ Real-time bucket policy change monitoring

**Severity Levels:** HIGH, MEDIUM, LOW

**Performance:** Checks up to 100 buckets per execution

---

### 4. EC2 Security (ENABLE_EC2)
**Status:** ✅ Enabled by default

- ✅ Security groups allowing SSH (22) from 0.0.0.0/0 (CRITICAL)
- ✅ Security groups allowing RDP (3389) from 0.0.0.0/0 (CRITICAL)
- ✅ Security groups allowing all traffic from 0.0.0.0/0 (CRITICAL)
- ✅ Security groups with IPv6 (::/0) exposure (CRITICAL)
- ✅ EC2 instances not requiring IMDSv2 (MEDIUM)
- ✅ Unencrypted EBS volumes in use (HIGH)
- ✅ Real-time security group change monitoring

**Severity Levels:** CRITICAL, HIGH, MEDIUM

**Performance:** Checks up to 100 security groups, instances, and volumes

---

### 5. GuardDuty (ENABLE_GUARDDUTY)
**Status:** ⚠️ Disabled by default (requires GuardDuty to be enabled)

- ✅ High-severity threat findings (severity >= 4)
- ✅ Active security threats detected
- ✅ Up to 50 findings per check

**Severity Levels:** CRITICAL

**Note:** Requires GuardDuty to be enabled in the AWS account

---

### 6. Security Hub (ENABLE_SECURITYHUB)
**Status:** ⚠️ Disabled by default (requires Security Hub to be enabled)

- ✅ Critical and high-severity findings
- ✅ Security standard violations
- ✅ Up to 50 findings per check

**Severity Levels:** CRITICAL

**Note:** Requires Security Hub to be enabled in the AWS account

---

### 7. AWS Config (ENABLE_CONFIG)
**Status:** ⚠️ Disabled by default (requires AWS Config to be enabled)

- ✅ AWS Config not enabled or not recording (HIGH)
- ✅ Non-compliant config rules (MEDIUM)
- ✅ Missing delivery channels (MEDIUM)
- ✅ Detailed compliance rule violations (LOW)
- ✅ Real-time config rule change monitoring

**Severity Levels:** HIGH, MEDIUM, LOW

**Note:** Requires AWS Config to be enabled in the AWS account

---

### 8. ECS Security (ENABLE_ECS)
**Status:** ✅ Enabled by default

- ✅ Containers with hardcoded secrets in environment variables (HIGH)
- ✅ Containers running in privileged mode (HIGH)
- ✅ Containers running as root user (MEDIUM)
- ✅ Services with public IP assignment enabled (MEDIUM)
- ✅ Real-time ECS service/task definition change monitoring

**Severity Levels:** HIGH, MEDIUM

**Performance:** Checks up to 100 clusters and services

---

### 9. EKS Security (ENABLE_EKS)
**Status:** ✅ Enabled by default

- ✅ Clusters with public endpoint access from 0.0.0.0/0 (HIGH)
- ✅ Clusters without private endpoint access (MEDIUM)
- ✅ Clusters without control plane logging (MEDIUM)
- ✅ Clusters without secrets encryption (HIGH)
- ✅ Clusters running outdated Kubernetes versions (MEDIUM)
- ✅ Missing log types (API, audit, authenticator, controllerManager, scheduler) (LOW)
- ✅ Real-time EKS cluster/nodegroup change monitoring

**Severity Levels:** HIGH, MEDIUM, LOW

**Performance:** Checks up to 100 clusters

---

## Event-Based Real-Time Monitoring

The system monitors CloudTrail events in real-time for the following services:

### Monitored Event Sources
- ✅ aws.iam
- ✅ aws.s3
- ✅ aws.ec2
- ✅ aws.cloudtrail
- ✅ aws.config
- ✅ aws.guardduty
- ✅ aws.securityhub
- ✅ aws.kms
- ✅ aws.secretsmanager
- ✅ aws.ecs
- ✅ aws.eks
- ✅ aws.rds
- ✅ aws.dynamodb
- ✅ aws.redshift
- ✅ aws.elasticache
- ✅ aws.es
- ✅ aws.workspaces
- ✅ aws.organizations

### Monitored Event Types
- CreateUser, DeleteUser
- CreateRole, DeleteRole, AttachRolePolicy, DetachRolePolicy
- PutBucketPolicy, DeleteBucketPolicy
- Security group operations (Authorize/Revoke Ingress/Egress)
- CloudTrail operations (Start/Stop Logging, Update/Delete Trail)
- Config operations (Start/Stop Recorder, Create/Delete Rules)
- ECS/EKS resource changes
- And many more (see template.yaml for full list)

---

## Features

### Core Capabilities
- ✅ Real-time CloudTrail event monitoring via EventBridge
- ✅ Periodic security posture checks (9 services)
- ✅ Slack notifications with rich formatting
- ✅ Event aggregation and grouping
- ✅ Whitelist support with wildcard patterns
- ✅ Critical event flagging
- ✅ MFA detection and root account monitoring

### Resilience & Reliability
- ✅ Exponential backoff retry logic (3 retries, 2s delay)
- ✅ Rate limiting (30 messages/minute)
- ✅ SQS queue with DLQ for failed events
- ✅ Message truncation (3000 chars max)
- ✅ Graceful error handling
- ✅ CloudWatch logging and metrics

### Performance
- ✅ Lambda reserved concurrency (5)
- ✅ Configurable timeout (default: 60s)
- ✅ Configurable memory (default: 256MB)
- ✅ Batch processing (10 events per batch)
- ✅ Pagination limits to prevent timeouts

---

## Configuration

### Feature Flags (Environment Variables)

All checks can be individually enabled/disabled:

```bash
ENABLE_GUARDDUTY=true      # Default: true
ENABLE_SECURITYHUB=true    # Default: true
ENABLE_IAM=true            # Default: true
ENABLE_CLOUDTRAIL=true     # Default: true
ENABLE_S3=true             # Default: true
ENABLE_EC2=true            # Default: true
ENABLE_CONFIG=true         # Default: true
ENABLE_ECS=true            # Default: true
ENABLE_EKS=true            # Default: true
```

### CloudFormation Parameters

All feature flags are exposed as CloudFormation parameters with sensible defaults:

- **Enabled by default:** IAM, CloudTrail, S3, EC2, ECS, EKS
- **Disabled by default:** GuardDuty, SecurityHub, Config (require pre-existing services)

### Terraform Variables

All feature flags are exposed as Terraform variables with the same defaults.

---

## IAM Permissions

The Lambda function requires read-only permissions for:

- **SQS:** ReceiveMessage, DeleteMessage, GetQueueAttributes
- **EC2:** DescribeSecurityGroups, DescribeInstances, DescribeVolumes
- **S3:** ListAllMyBuckets, GetBucket* (PublicAccessBlock, Encryption, Versioning, Logging, Policy, Location)
- **CloudTrail:** LookupEvents, DescribeTrails, GetTrailStatus
- **IAM:** ListUsers, ListMFADevices, GetLoginProfile, ListPolicies, GetPolicyVersion, ListAccessKeys
- **GuardDuty:** GetFindings, ListDetectors, ListFindings
- **Security Hub:** GetFindings, BatchImportFindings
- **Config:** Get/DescribeCompliance*, DescribeConfigurationRecorders, DescribeDeliveryChannels
- **ECS:** List/DescribeClusters, List/DescribeServices, List/DescribeTaskDefinition
- **EKS:** ListClusters, DescribeCluster, ListNodegroups, DescribeNodegroup

All permissions follow the principle of least privilege.

---

## Architecture

```
┌──────────────────┐
│  AWS Services    │
│  (CloudTrail,    │
│   GuardDuty,     │
│   etc.)          │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   EventBridge    │
│   (Event Rule)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐         ┌──────────────────┐
│   SQS Queue      │────────▶│   SQS DLQ        │
│  (Buffer + 14d)  │         │  (Failed msgs)   │
└────────┬─────────┘         └──────────────────┘
         │
         ▼
┌──────────────────┐
│  Lambda Function │
│  - Event Handler │
│  - Check Registry│
│  - 9 Check Mods  │
└────────┬─────────┘
         │
         ├─────────────────┐
         ▼                 ▼
┌──────────────────┐  ┌──────────────────┐
│  Slack Notifier  │  │  CloudWatch      │
│  (Retry + Rate)  │  │  (Logs + Metrics)│
└──────────────────┘  └──────────────────┘
```

---

## Extensibility

### Adding New Checks

The system uses a **registry-based architecture** that makes adding new checks extremely easy:

1. Create a new check module in `src/security_notifier/checks/`
2. Register it in `checks/__init__.py`
3. Add a config flag in `config.py`
4. Update CloudFormation/Terraform (optional)

**See:** `docs/DEVELOPER_GUIDE.md` for complete step-by-step guide with examples

### Example: Adding a Lambda Check

```python
# src/security_notifier/checks/lambda_check.py
def run(config, clients):
    events = []
    lambda_client = clients.get("lambda")
    functions = lambda_client.list_functions(MaxItems=100)
    
    for func in functions.get("Functions", []):
        if not func.get("VpcConfig"):
            events.append({
                "severity": "MEDIUM",
                "description": f"Lambda {func['FunctionName']} not in VPC"
            })
    
    return events
```

That's it! The handler automatically discovers and runs it.

---

## Testing

### Test Coverage

- ✅ 16 unit tests (all passing)
- ✅ Handler tests
- ✅ Config tests
- ✅ Formatter tests
- ✅ Slack notifier tests
- ✅ All 9 check modules tested

### Running Tests

```bash
make test
# or
PYTHONPATH=src python -m pytest tests/ -v
```

**Note:** Tests require dependencies to be installed (`pip install -r requirements-dev.txt`). This is handled automatically by the GitHub Actions CI/CD workflow and does not affect Lambda deployment, which uses `make package` to bundle all dependencies.

---

## Cost Estimate

For **10,000 events/month** with all checks enabled:

- EventBridge: $0.10
- SQS: $0.04
- Lambda: $0.20
- CloudWatch Logs: $0.50
- **Total: ~$0.84/month**

Scales linearly with event volume.

---

## Documentation

### Available Documentation

1. **README.md** - Main documentation with quick start, configuration, and usage
2. **docs/DEPLOYMENT.md** - Complete deployment guide for all methods
3. **docs/DEVELOPER_GUIDE.md** - Step-by-step guide for adding new checks
4. **terraform/README.md** - Terraform module documentation
5. **examples/** - Basic and advanced Terraform examples

---

## Security Best Practices

The system implements:

- ✅ Principle of least privilege IAM
- ✅ No hardcoded credentials
- ✅ Encryption in transit (HTTPS)
- ✅ Encryption at rest (SQS)
- ✅ CloudWatch audit logs
- ✅ MFA detection
- ✅ Root account monitoring
- ✅ Graceful error handling
- ✅ Rate limiting and retry logic

---

## Known Limitations

1. **Performance Limits:**
   - S3: Checks up to 100 buckets
   - EC2: Checks up to 100 resources per category
   - ECS: Checks up to 100 clusters
   - EKS: Checks up to 100 clusters

2. **Service Dependencies:**
   - GuardDuty, Security Hub, and Config checks require pre-existing service enablement

3. **Regional:**
   - Deployed per region
   - Multi-region trails detected but not required

---

## Version History

### v3.0.0 (Current)
- Added 5 new security check modules (S3, EC2, ECS, EKS, Config)
- Expanded from 4 to 9 total security checks
- Updated all documentation
- Added comprehensive developer guide
- Improved test coverage (16 tests)
- Enhanced CloudFormation and Terraform templates

### v2.0.0
- Optimized to 4 core checks (GuardDuty, Security Hub, IAM, CloudTrail)
- Removed metrics collection
- Simplified configuration

### v1.0.0
- Initial release

---

## Support & Contributing

- **GitHub:** https://github.com/Parthasarathi7722/aws-security-notification
- **Issues:** Use GitHub Issues for bug reports and feature requests
- **PRs:** Contributions welcome! See DEVELOPER_GUIDE.md

---

## License

MIT License - See LICENSE file for details

---

**Last Validated:** February 8, 2026  
**All tests passing:** ✅  
**CloudFormation template:** ✅  
**Terraform module:** ✅  
**Documentation:** ✅  

**Status: Production Ready** 🚀

