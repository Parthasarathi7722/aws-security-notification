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

