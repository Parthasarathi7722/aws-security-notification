"""
AWS Security Notification System
Monitors AWS security events and sends Slack alerts with retry logic and rate limiting.

Author: Security Team
Version: 2.1.0 (Streamlined)
"""
import json
import os
import time
import boto3
import requests
from botocore.exceptions import ClientError
import fnmatch
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
import traceback
import logging

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration from environment variables."""
    def __init__(self):
        self.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not self.slack_webhook_url:
            raise ValueError("SLACK_WEBHOOK_URL is required")

        self.account_name = os.getenv("ACCOUNT_NAME", "AWS Account")
        self.whitelist_resources = [x.strip() for x in os.getenv("WHITELIST_RESOURCES", "").split(",") if x.strip()]
        self.critical_events = [x.strip() for x in os.getenv("CRITICAL_EVENTS", "").split(",") if x.strip()]

        # Feature flags
        self.enable_guardduty = os.getenv("ENABLE_GUARDDUTY", "false").lower() == "true"
        self.enable_securityhub = os.getenv("ENABLE_SECURITYHUB", "false").lower() == "true"
        self.enable_config = os.getenv("ENABLE_CONFIG", "false").lower() == "true"
        self.enable_ecs = os.getenv("ENABLE_ECS", "true").lower() == "true"
        self.enable_eks = os.getenv("ENABLE_EKS", "true").lower() == "true"
        self.enable_rds = os.getenv("ENABLE_RDS", "true").lower() == "true"
        self.enable_lambda_checks = os.getenv("ENABLE_LAMBDA_CHECKS", "true").lower() == "true"
        self.enable_iam_checks = os.getenv("ENABLE_IAM_CHECKS", "true").lower() == "true"
        self.enable_s3_checks = os.getenv("ENABLE_S3_CHECKS", "true").lower() == "true"
        self.enable_cloudtrail_checks = os.getenv("ENABLE_CLOUDTRAIL_CHECKS", "true").lower() == "true"
        self.enable_kms_checks = os.getenv("ENABLE_KMS_CHECKS", "true").lower() == "true"
        self.enable_secrets_checks = os.getenv("ENABLE_SECRETS_CHECKS", "true").lower() == "true"

        # Settings
        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        self.retry_delay = int(os.getenv("RETRY_DELAY_SECONDS", "2"))
        self.rate_limit = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))
        self.max_message_length = int(os.getenv("MAX_SLACK_MESSAGE_LENGTH", "3000"))

# Initialize
config = Config()
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# AWS clients
s3_client = boto3.client("s3")
ec2_client = boto3.client("ec2")
guardduty_client = boto3.client("guardduty")
securityhub_client = boto3.client("securityhub")
config_client = boto3.client("config")
ecs_client = boto3.client("ecs")
eks_client = boto3.client("eks")
cloudwatch_client = boto3.client("cloudwatch")
rds_client = boto3.client("rds")
lambda_client = boto3.client("lambda")
iam_client = boto3.client("iam")
kms_client = boto3.client("kms")
cloudtrail_client = boto3.client("cloudtrail")
secretsmanager_client = boto3.client("secretsmanager")

# Metrics and rate limiter
metrics = {'events_processed': 0, 'events_filtered': 0, 'notifications_sent': 0, 'notifications_failed': 0, 'errors': 0}
rate_limiter = deque(maxlen=config.rate_limit)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def safe_get(dictionary, *keys):
    """Safely get nested dictionary value."""
    for key in keys:
        if dictionary is None or key not in dictionary:
            return None
        dictionary = dictionary[key]
    return dictionary

def is_whitelisted(event_arn):
    """Check if ARN matches whitelist (supports wildcards)."""
    if not event_arn or event_arn == "Unknown ARN":
        return False
    return any(fnmatch.fnmatch(event_arn, pattern) for pattern in config.whitelist_resources)

def is_critical_event(event_name):
    """Check if event is critical."""
    return event_name in config.critical_events if event_name else False

# ============================================================================
# SLACK NOTIFICATION
# ============================================================================

def send_to_slack(message, is_critical=False):
    """Send message to Slack with retry and rate limiting."""
    global rate_limiter

    # Truncate long messages
    if len(message) > config.max_message_length:
        message = message[:config.max_message_length - 50] + "\n...[truncated]"

    if is_critical:
        message = f"🚨 *CRITICAL ALERT* 🚨\n{message}"

    payload = {"text": message, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": message}}]}

    for attempt in range(config.max_retries):
        try:
            # Rate limit check
            now = datetime.now(timezone.utc)
            while rate_limiter and rate_limiter[0] < now - timedelta(seconds=60):
                rate_limiter.popleft()

            if len(rate_limiter) >= config.rate_limit:
                time.sleep(1)
                continue

            response = requests.post(config.slack_webhook_url, json=payload, timeout=10)
            rate_limiter.append(now)

            if response.status_code == 200:
                metrics['notifications_sent'] += 1
                return True
            elif response.status_code == 429:
                time.sleep(int(response.headers.get("Retry-After", config.retry_delay)))
            else:
                if attempt < config.max_retries - 1:
                    time.sleep(config.retry_delay * (attempt + 1))
        except Exception as e:
            logger.error(f"Slack error (attempt {attempt + 1}): {str(e)}")
            if attempt < config.max_retries - 1:
                time.sleep(config.retry_delay * (attempt + 1))

    metrics['notifications_failed'] += 1
    return False

def publish_metrics():
    """Publish metrics to CloudWatch."""
    try:
        cloudwatch_client.put_metric_data(
            Namespace='SecurityNotifications',
            MetricData=[
                {'MetricName': k, 'Value': v, 'Unit': 'Count', 'Timestamp': datetime.now(timezone.utc)}
                for k, v in metrics.items()
            ]
        )
        logger.info(f"Metrics: {metrics}")
    except Exception as e:
        logger.error(f"Metrics error: {str(e)}")

# ============================================================================
# AWS SERVICE INTEGRATIONS
# ============================================================================

def get_guardduty_findings():
    """Get high-severity GuardDuty findings."""
    if not config.enable_guardduty:
        return []
    try:
        detectors = guardduty_client.list_detectors()
        if not detectors.get('DetectorIds'):
            return []
        findings = guardduty_client.list_findings(
            DetectorId=detectors['DetectorIds'][0],
            FindingCriteria={'Criterion': {'severity': {'Gte': 4}}},
            MaxResults=50
        )
        return findings.get('FindingIds', [])
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') != 'BadRequestException':
            logger.warning(f"GuardDuty error: {str(e)}")
        return []
    except Exception as e:
        metrics['errors'] += 1
        return []

def get_securityhub_findings():
    """Get critical/high Security Hub findings."""
    if not config.enable_securityhub:
        return []
    try:
        findings = securityhub_client.get_findings(
            Filters={'SeverityLabel': [
                {'Comparison': 'EQUALS', 'Value': 'CRITICAL'},
                {'Comparison': 'EQUALS', 'Value': 'HIGH'}
            ]},
            MaxResults=50
        )
        return findings.get('Findings', [])
    except ClientError:
        return []
    except Exception:
        metrics['errors'] += 1
        return []

def get_config_compliance():
    """Get AWS Config compliance status."""
    if not config.enable_config:
        return []
    try:
        rules = config_client.describe_config_rules()
        compliance = []
        for rule in rules.get('ConfigRules', []):
            try:
                result = config_client.get_compliance_details_by_config_rule(
                    ConfigRuleName=rule['ConfigRuleName']
                )
                if result.get('EvaluationResults'):
                    compliance.append({
                        'rule_name': rule['ConfigRuleName'],
                        'compliance': result['EvaluationResults'][0]['ComplianceType']
                    })
            except:
                continue
        return compliance
    except:
        return []

def get_ecs_security_events():
    """Get ECS security issues."""
    if not config.enable_ecs:
        return []
    events = []
    try:
        clusters = ecs_client.list_clusters(maxResults=10)
        for cluster_arn in clusters.get('clusterArns', []):
            try:
                details = ecs_client.describe_clusters(clusters=[cluster_arn])
                cluster = details['clusters'][0]
                if cluster.get('status') != 'ACTIVE':
                    events.append({
                        'type': 'ECS_CLUSTER_INACTIVE',
                        'severity': 'HIGH',
                        'cluster': cluster.get('clusterName'),
                        'description': f"Cluster {cluster.get('clusterName')} is {cluster.get('status')}"
                    })
            except:
                continue
    except:
        pass
    return events

def get_eks_security_events():
    """Get EKS security issues."""
    if not config.enable_eks:
        return []
    events = []
    try:
        clusters = eks_client.list_clusters(maxResults=10)
        for cluster_name in clusters.get('clusters', []):
            try:
                details = eks_client.describe_cluster(name=cluster_name)
                cluster = details['cluster']
                if cluster.get('status') != 'ACTIVE':
                    events.append({
                        'type': 'EKS_CLUSTER_INACTIVE',
                        'severity': 'HIGH',
                        'cluster': cluster_name,
                        'description': f"Cluster {cluster_name} is {cluster.get('status')}"
                    })
                if cluster.get('resourcesVpcConfig', {}).get('endpointPublicAccess'):
                    events.append({
                        'type': 'EKS_PUBLIC_ACCESS',
                        'severity': 'MEDIUM',
                        'cluster': cluster_name,
                        'description': f"Public access enabled for {cluster_name}"
                    })
            except:
                continue
    except:
        pass
    return events

def get_rds_security_events():
    """Get RDS security issues - CRITICAL."""
    if not config.enable_rds:
        return []
    events = []
    try:
        # Check RDS instances
        response = rds_client.describe_db_instances(MaxRecords=50)
        for db in response.get('DBInstances', []):
            db_id = db.get('DBInstanceIdentifier')

            # Critical: Public access
            if db.get('PubliclyAccessible'):
                events.append({
                    'type': 'RDS_PUBLIC_ACCESS',
                    'severity': 'CRITICAL',
                    'resource': db_id,
                    'description': f"CRITICAL: Database {db_id} is publicly accessible"
                })

            # Critical: No encryption
            if not db.get('StorageEncrypted'):
                events.append({
                    'type': 'RDS_UNENCRYPTED',
                    'severity': 'CRITICAL',
                    'resource': db_id,
                    'description': f"CRITICAL: Database {db_id} storage is not encrypted"
                })

            # High: No automated backups
            if db.get('BackupRetentionPeriod', 0) == 0:
                events.append({
                    'type': 'RDS_NO_BACKUPS',
                    'severity': 'HIGH',
                    'resource': db_id,
                    'description': f"Database {db_id} has no automated backups enabled"
                })

            # High: Deletion protection disabled
            if not db.get('DeletionProtection', False):
                events.append({
                    'type': 'RDS_NO_DELETE_PROTECTION',
                    'severity': 'HIGH',
                    'resource': db_id,
                    'description': f"Database {db_id} has deletion protection disabled"
                })
    except Exception as e:
        logger.error(f"RDS check error: {str(e)}")
        metrics['errors'] += 1
    return events

def get_lambda_security_events():
    """Get Lambda security issues - CRITICAL."""
    if not config.enable_lambda_checks:
        return []
    events = []
    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate(MaxItems=100):
            for func in page.get('Functions', []):
                func_name = func.get('FunctionName')

                try:
                    # Check function policy for public access
                    policy = lambda_client.get_policy(FunctionName=func_name)
                    policy_doc = json.loads(policy['Policy'])
                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Principal') == '*' or statement.get('Principal', {}).get('AWS') == '*':
                            events.append({
                                'type': 'LAMBDA_PUBLIC_POLICY',
                                'severity': 'CRITICAL',
                                'resource': func_name,
                                'description': f"CRITICAL: Lambda {func_name} has public policy allowing anyone to invoke"
                            })
                except ClientError as e:
                    if e.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
                        pass  # Function has no policy, which is OK

                # High: Environment variables without encryption
                if func.get('Environment', {}).get('Variables'):
                    if not func.get('KMSKeyArn'):
                        events.append({
                            'type': 'LAMBDA_UNENCRYPTED_ENV',
                            'severity': 'HIGH',
                            'resource': func_name,
                            'description': f"Lambda {func_name} has environment variables but no KMS encryption"
                        })

                # Medium: VPC without security
                if func.get('VpcConfig') and func.get('VpcConfig', {}).get('VpcId'):
                    if not func.get('VpcConfig', {}).get('SecurityGroupIds'):
                        events.append({
                            'type': 'LAMBDA_NO_SG',
                            'severity': 'MEDIUM',
                            'resource': func_name,
                            'description': f"Lambda {func_name} in VPC but no security groups"
                        })
    except Exception as e:
        logger.error(f"Lambda check error: {str(e)}")
        metrics['errors'] += 1
    return events

def get_iam_security_events():
    """Get IAM security issues - CRITICAL."""
    if not config.enable_iam_checks:
        return []
    events = []
    try:
        # Check for users without MFA
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate(MaxItems=100):
            for user in page.get('Users', []):
                username = user.get('UserName')
                try:
                    mfa = iam_client.list_mfa_devices(UserName=username)
                    if not mfa.get('MFADevices'):
                        # Check if user has console access
                        try:
                            login_profile = iam_client.get_login_profile(UserName=username)
                            events.append({
                                'type': 'IAM_NO_MFA',
                                'severity': 'HIGH',
                                'resource': username,
                                'description': f"User {username} has console access but no MFA enabled"
                            })
                        except ClientError:
                            pass  # No console access
                except Exception:
                    pass

        # Check for overly permissive policies
        policies = iam_client.list_policies(Scope='Local', MaxItems=50)
        for policy in policies.get('Policies', []):
            try:
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )
                doc = policy_version['PolicyVersion']['Document']
                for statement in doc.get('Statement', []):
                    # Check for admin access
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if '*' in actions or 'iam:*' in actions:
                            resources = statement.get('Resource', [])
                            if isinstance(resources, str):
                                resources = [resources]
                            if '*' in resources:
                                events.append({
                                    'type': 'IAM_ADMIN_POLICY',
                                    'severity': 'HIGH',
                                    'resource': policy['PolicyName'],
                                    'description': f"Policy {policy['PolicyName']} grants admin access (*:* on *)"
                                })
            except Exception:
                pass

        # Check for access keys older than 90 days
        for page in paginator.paginate(MaxItems=100):
            for user in page.get('Users', []):
                username = user.get('UserName')
                try:
                    keys = iam_client.list_access_keys(UserName=username)
                    for key in keys.get('AccessKeyMetadata', []):
                        if key.get('Status') == 'Active':
                            age_days = (datetime.now(timezone.utc) - key['CreateDate']).days
                            if age_days > 90:
                                events.append({
                                    'type': 'IAM_OLD_ACCESS_KEY',
                                    'severity': 'MEDIUM',
                                    'resource': f"{username}/{key['AccessKeyId']}",
                                    'description': f"Access key for {username} is {age_days} days old (>90 days)"
                                })
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"IAM check error: {str(e)}")
        metrics['errors'] += 1
    return events

def get_s3_security_events():
    """Get S3 security issues - CRITICAL."""
    if not config.enable_s3_checks:
        return []
    events = []
    try:
        buckets = s3_client.list_buckets().get('Buckets', [])
        for bucket in buckets[:50]:  # Limit to 50 buckets
            bucket_name = bucket['Name']
            try:
                # Check public access block
                try:
                    public_block = s3_client.get_public_access_block(Bucket=bucket_name)
                    config_data = public_block.get('PublicAccessBlockConfiguration', {})
                    if not all([
                        config_data.get('BlockPublicAcls'),
                        config_data.get('IgnorePublicAcls'),
                        config_data.get('BlockPublicPolicy'),
                        config_data.get('RestrictPublicBuckets')
                    ]):
                        events.append({
                            'type': 'S3_PUBLIC_ACCESS_ALLOWED',
                            'severity': 'CRITICAL',
                            'resource': bucket_name,
                            'description': f"CRITICAL: Bucket {bucket_name} does not block all public access"
                        })
                except ClientError as e:
                    if e.response.get('Error', {}).get('Code') == 'NoSuchPublicAccessBlockConfiguration':
                        events.append({
                            'type': 'S3_NO_PUBLIC_BLOCK',
                            'severity': 'CRITICAL',
                            'resource': bucket_name,
                            'description': f"CRITICAL: Bucket {bucket_name} has no public access block configured"
                        })

                # Check encryption
                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response.get('Error', {}).get('Code') == 'ServerSideEncryptionConfigurationNotFoundError':
                        events.append({
                            'type': 'S3_NO_ENCRYPTION',
                            'severity': 'HIGH',
                            'resource': bucket_name,
                            'description': f"Bucket {bucket_name} has no encryption enabled"
                        })

                # Check versioning
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    events.append({
                        'type': 'S3_NO_VERSIONING',
                        'severity': 'MEDIUM',
                        'resource': bucket_name,
                        'description': f"Bucket {bucket_name} does not have versioning enabled"
                    })
            except Exception as e:
                logger.debug(f"Error checking bucket {bucket_name}: {str(e)}")
    except Exception as e:
        logger.error(f"S3 check error: {str(e)}")
        metrics['errors'] += 1
    return events

def get_cloudtrail_security_events():
    """Get CloudTrail security issues - CRITICAL."""
    if not config.enable_cloudtrail_checks:
        return []
    events = []
    try:
        trails = cloudtrail_client.describe_trails().get('trailList', [])
        if not trails:
            events.append({
                'type': 'CLOUDTRAIL_NO_TRAIL',
                'severity': 'CRITICAL',
                'resource': 'Account',
                'description': 'CRITICAL: No CloudTrail trails configured in this region'
            })
        else:
            for trail in trails:
                trail_name = trail.get('Name')
                # Check if trail is logging
                status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                if not status.get('IsLogging'):
                    events.append({
                        'type': 'CLOUDTRAIL_NOT_LOGGING',
                        'severity': 'CRITICAL',
                        'resource': trail_name,
                        'description': f"CRITICAL: CloudTrail {trail_name} is not logging"
                    })

                # Check if multi-region
                if not trail.get('IsMultiRegionTrail'):
                    events.append({
                        'type': 'CLOUDTRAIL_SINGLE_REGION',
                        'severity': 'HIGH',
                        'resource': trail_name,
                        'description': f"CloudTrail {trail_name} is not multi-region"
                    })

                # Check log file validation
                if not trail.get('LogFileValidationEnabled'):
                    events.append({
                        'type': 'CLOUDTRAIL_NO_VALIDATION',
                        'severity': 'HIGH',
                        'resource': trail_name,
                        'description': f"CloudTrail {trail_name} does not have log file validation"
                    })
    except Exception as e:
        logger.error(f"CloudTrail check error: {str(e)}")
        metrics['errors'] += 1
    return events

def get_kms_security_events():
    """Get KMS security issues."""
    if not config.enable_kms_checks:
        return []
    events = []
    try:
        paginator = kms_client.get_paginator('list_keys')
        for page in paginator.paginate(Limit=100):
            for key in page.get('Keys', []):
                key_id = key['KeyId']
                try:
                    metadata = kms_client.describe_key(KeyId=key_id)
                    key_data = metadata['KeyMetadata']

                    # Skip AWS managed keys
                    if key_data.get('KeyManager') == 'AWS':
                        continue

                    # Check rotation
                    if key_data.get('KeyState') == 'Enabled':
                        rotation = kms_client.get_key_rotation_status(KeyId=key_id)
                        if not rotation.get('KeyRotationEnabled'):
                            events.append({
                                'type': 'KMS_NO_ROTATION',
                                'severity': 'MEDIUM',
                                'resource': key_data.get('Arn'),
                                'description': f"KMS key {key_data.get('Arn', key_id)} does not have automatic rotation enabled"
                            })
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"KMS check error: {str(e)}")
        metrics['errors'] += 1
    return events

def get_secrets_security_events():
    """Get Secrets Manager security issues."""
    if not config.enable_secrets_checks:
        return []
    events = []
    try:
        paginator = secretsmanager_client.get_paginator('list_secrets')
        for page in paginator.paginate(MaxResults=100):
            for secret in page.get('SecretList', []):
                secret_name = secret.get('Name')

                # Check rotation
                if not secret.get('RotationEnabled'):
                    events.append({
                        'type': 'SECRET_NO_ROTATION',
                        'severity': 'MEDIUM',
                        'resource': secret_name,
                        'description': f"Secret {secret_name} does not have automatic rotation enabled"
                    })

                # Check if secret has been accessed recently (unused secrets)
                if secret.get('LastAccessedDate'):
                    days_since_access = (datetime.now(timezone.utc) - secret['LastAccessedDate']).days
                    if days_since_access > 90:
                        events.append({
                            'type': 'SECRET_UNUSED',
                            'severity': 'LOW',
                            'resource': secret_name,
                            'description': f"Secret {secret_name} has not been accessed in {days_since_access} days"
                        })
    except Exception as e:
        logger.error(f"Secrets Manager check error: {str(e)}")
        metrics['errors'] += 1
    return events

# ============================================================================
# EVENT FORMATTING
# ============================================================================

def format_event_message(detail):
    """Format event details into Slack message."""
    try:
        event_name = detail.get("eventName", "Unknown")
        error_code = detail.get("errorCode", "N/A")
        user_identity = detail.get("userIdentity", {})
        username = safe_get(user_identity, "sessionContext", "sessionIssuer", "userName") or safe_get(user_identity, "userName") or "Unknown"
        account_id = user_identity.get("accountId", "Unknown")
        arn = user_identity.get("arn", "Unknown")
        user_type = user_identity.get("type", "Unknown")
        mfa = safe_get(user_identity, "sessionContext", "attributes", "mfaAuthenticated") or "false"
        source_ip = detail.get("sourceIPAddress", "Unknown")
        region = detail.get("awsRegion", "Unknown")
        event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())

        # Security risks
        risks = []
        if mfa.lower() != "true":
            risks.append("⚠️ No MFA")
        if user_type == "Root":
            risks.append("⚠️ Root account")
        if error_code != "N/A":
            risks.append(f"⚠️ Denied: {error_code}")

        msg = (
            f"*{config.account_name} ({account_id})*\n"
            f"*Event:* {event_name}\n"
            f"*User:* {username} ({user_type})\n"
            f"*Source IP:* {source_ip}\n"
            f"*Region:* {region}\n"
            f"*Time:* {event_time}\n"
        )

        if risks:
            msg += "*Risks:* " + ", ".join(risks) + "\n"

        return msg
    except Exception as e:
        return f"*{config.account_name}*\nError formatting message: {str(e)}"

# ============================================================================
# LAMBDA HANDLER
# ============================================================================

def lambda_handler(event, context):
    """Main Lambda handler."""
    request_id = context.request_id if context else "local"
    logger.info(f"Processing {len(event.get('Records', []))} records - {request_id}")

    # Reset metrics
    for key in metrics:
        metrics[key] = 0

    try:
        event_groups = defaultdict(list)

        # Process SQS messages
        for record in event.get("Records", []):
            try:
                metrics['events_processed'] += 1
                sqs_body = json.loads(record["body"])
                detail = sqs_body.get("detail", {})

                # Check whitelist
                event_arn = safe_get(detail, "userIdentity", "arn") or "Unknown"
                if is_whitelisted(event_arn):
                    metrics['events_filtered'] += 1
                    continue

                # Group events
                event_name = detail.get("eventName", "Unknown")
                resource_arn = detail.get("resources", [{}])[0].get("ARN", "Unknown")
                event_groups[f"{event_name}:{resource_arn}"].append(detail)

            except Exception as e:
                logger.error(f"Record error: {str(e)}")
                metrics['errors'] += 1
                continue

        # Send notifications
        for group_key, details in event_groups.items():
            try:
                event_name = details[0].get("eventName")
                is_critical = is_critical_event(event_name)

                if len(details) > 1:
                    msg = (
                        f"*Aggregated Alert - {config.account_name}*\n"
                        f"*Event:* {event_name}\n"
                        f"*Count:* {len(details)} events\n\n"
                    )
                    for i, detail in enumerate(details[:3], 1):
                        msg += f"*Event {i}:*\n{format_event_message(detail)}\n"
                    if len(details) > 3:
                        msg += f"\n...and {len(details) - 3} more"
                else:
                    msg = format_event_message(details[0])

                send_to_slack(msg, is_critical)
            except Exception as e:
                logger.error(f"Group error: {str(e)}")
                metrics['errors'] += 1

        # Optional service checks
        if config.enable_guardduty:
            findings = get_guardduty_findings()
            if findings:
                msg = f"*GuardDuty - {config.account_name}*\n{len(findings)} high-severity findings"
                send_to_slack(msg, True)

        if config.enable_securityhub:
            findings = get_securityhub_findings()
            if findings:
                msg = f"*Security Hub - {config.account_name}*\n{len(findings)} critical/high findings"
                send_to_slack(msg, True)

        if config.enable_config:
            compliance = get_config_compliance()
            if compliance:
                non_compliant = [r for r in compliance if r['compliance'] != 'COMPLIANT']
                if non_compliant:
                    msg = f"*Config - {config.account_name}*\n{len(non_compliant)} non-compliant rules"
                    send_to_slack(msg, False)

        if config.enable_ecs:
            events = get_ecs_security_events()
            if events:
                msg = f"*ECS Security - {config.account_name}*\n" + "\n".join([e['description'] for e in events[:5]])
                send_to_slack(msg, any(e['severity'] == 'HIGH' for e in events))

        if config.enable_eks:
            events = get_eks_security_events()
            if events:
                msg = f"*EKS Security - {config.account_name}*\n" + "\n".join([e['description'] for e in events[:5]])
                send_to_slack(msg, any(e['severity'] == 'HIGH' for e in events))

        # CRITICAL: RDS Security Checks
        if config.enable_rds:
            events = get_rds_security_events()
            if events:
                critical_events = [e for e in events if e['severity'] == 'CRITICAL']
                msg = f"*RDS Security - {config.account_name}*\n"
                for event in events[:10]:
                    msg += f"[{event['severity']}] {event['description']}\n"
                send_to_slack(msg, len(critical_events) > 0)

        # CRITICAL: Lambda Security Checks
        if config.enable_lambda_checks:
            events = get_lambda_security_events()
            if events:
                critical_events = [e for e in events if e['severity'] == 'CRITICAL']
                msg = f"*Lambda Security - {config.account_name}*\n"
                for event in events[:10]:
                    msg += f"[{event['severity']}] {event['description']}\n"
                send_to_slack(msg, len(critical_events) > 0)

        # CRITICAL: IAM Security Checks
        if config.enable_iam_checks:
            events = get_iam_security_events()
            if events:
                critical_events = [e for e in events if e['severity'] == 'CRITICAL']
                msg = f"*IAM Security - {config.account_name}*\n"
                for event in events[:10]:
                    msg += f"[{event['severity']}] {event['description']}\n"
                send_to_slack(msg, len(critical_events) > 0)

        # CRITICAL: S3 Security Checks
        if config.enable_s3_checks:
            events = get_s3_security_events()
            if events:
                critical_events = [e for e in events if e['severity'] == 'CRITICAL']
                msg = f"*S3 Security - {config.account_name}*\n"
                for event in events[:10]:
                    msg += f"[{event['severity']}] {event['description']}\n"
                send_to_slack(msg, len(critical_events) > 0)

        # CRITICAL: CloudTrail Security Checks
        if config.enable_cloudtrail_checks:
            events = get_cloudtrail_security_events()
            if events:
                critical_events = [e for e in events if e['severity'] == 'CRITICAL']
                msg = f"*CloudTrail Security - {config.account_name}*\n"
                for event in events[:10]:
                    msg += f"[{event['severity']}] {event['description']}\n"
                send_to_slack(msg, len(critical_events) > 0)

        # KMS Security Checks
        if config.enable_kms_checks:
            events = get_kms_security_events()
            if events:
                msg = f"*KMS Security - {config.account_name}*\n"
                for event in events[:10]:
                    msg += f"[{event['severity']}] {event['description']}\n"
                send_to_slack(msg, False)

        # Secrets Manager Checks
        if config.enable_secrets_checks:
            events = get_secrets_security_events()
            if events:
                msg = f"*Secrets Manager - {config.account_name}*\n"
                for event in events[:10]:
                    msg += f"[{event['severity']}] {event['description']}\n"
                send_to_slack(msg, False)

        # Publish metrics
        publish_metrics()

        logger.info(f"Complete: {metrics}")
        return {"statusCode": 200, "body": json.dumps({"message": "Success", "metrics": metrics})}

    except Exception as e:
        logger.error(f"Handler error: {str(e)}\n{traceback.format_exc()}")
        metrics['errors'] += 1

        try:
            send_to_slack(f"*Error - {config.account_name}*\n{str(e)}", True)
            publish_metrics()
        except:
            pass

        return {"statusCode": 500, "body": json.dumps({"error": str(e), "metrics": metrics})}

