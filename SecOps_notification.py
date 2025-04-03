import json
import os
import requests
import boto3
from botocore.exceptions import ClientError
import fnmatch
from collections import defaultdict
from datetime import datetime, timezone
import re

# Initialize AWS clients
s3_client = boto3.client("s3")
ec2_client = boto3.client("ec2")
guardduty_client = boto3.client("guardduty")
securityhub_client = boto3.client("securityhub")
config_client = boto3.client("config")
kms_client = boto3.client("kms")
secretsmanager_client = boto3.client("secretsmanager")
ecs_client = boto3.client("ecs")
eks_client = boto3.client("eks")

# Environment variables
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
ACCOUNT_NAME = os.getenv("ACCOUNT_NAME", "Unknown Account")
WHITELIST_RESOURCES = os.getenv("WHITELIST_RESOURCES", "").split(",")
CRITICAL_EVENTS = os.getenv("CRITICAL_EVENTS", "").split(",")
ENABLE_GUARDDUTY = os.getenv("ENABLE_GUARDDUTY", "false").lower() == "true"
ENABLE_SECURITYHUB = os.getenv("ENABLE_SECURITYHUB", "false").lower() == "true"
ENABLE_CONFIG = os.getenv("ENABLE_CONFIG", "false").lower() == "true"
ENABLE_ECS = os.getenv("ENABLE_ECS", "true").lower() == "true"
ENABLE_EKS = os.getenv("ENABLE_EKS", "true").lower() == "true"

# Ensure Slack Webhook URL is provided
if not SLACK_WEBHOOK_URL:
    raise ValueError("SLACK_WEBHOOK_URL environment variable is missing!")

def get_whitelisted_arns():
    """Retrieve and clean whitelisted ARNs from environment variable."""
    return [arn.strip() for arn in WHITELIST_RESOURCES if arn.strip()]

def is_whitelisted(event_arn):
    """Check if the event ARN matches any whitelisted ARN (supports wildcards)."""
    if not event_arn or event_arn == "Unknown ARN":
        return False

    whitelist = get_whitelisted_arns()
    for whitelisted_arn in whitelist:
        if fnmatch.fnmatch(event_arn, whitelisted_arn):
            return True
    return False

def is_critical_event(event_name):
    """Check if the event is considered critical based on environment variable."""
    if not event_name:
        return False
    critical_events = [event.strip() for event in CRITICAL_EVENTS if event.strip()]
    return event_name in critical_events

def send_to_slack(message, is_critical=False):
    """Send a formatted message to Slack with critical event highlighting."""
    try:
        if is_critical:
            message = f"🚨 *CRITICAL SECURITY ALERT* 🚨\n{message}"
        
        slack_message = {
            "text": message,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        }
        
        response = requests.post(SLACK_WEBHOOK_URL, json=slack_message)
        if response.status_code != 200:
            raise ValueError(f"Slack returned error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"Failed to send message to Slack: {str(e)}")

def safe_get(dictionary, *keys):
    """Safely get a nested value from a dictionary."""
    for key in keys:
        if dictionary is None or key not in dictionary:
            return None
        dictionary = dictionary[key]
    return dictionary

def get_guardduty_findings():
    """Retrieve recent GuardDuty findings."""
    if not ENABLE_GUARDDUTY:
        return []
    
    try:
        detectors = guardduty_client.list_detectors()
        if not detectors.get('DetectorIds'):
            return []
        
        detector_id = detectors['DetectorIds'][0]
        findings = guardduty_client.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                'Criterion': {
                    'severity': {
                        'Gte': 4  # High severity findings
                    }
                }
            },
            MaxResults=50
        )
        
        return findings.get('FindingIds', [])
    except Exception as e:
        print(f"Error retrieving GuardDuty findings: {str(e)}")
        return []

def get_securityhub_findings():
    """Retrieve recent Security Hub findings."""
    if not ENABLE_SECURITYHUB:
        return []
    
    try:
        findings = securityhub_client.get_findings(
            Filters={
                'SeverityLabel': [
                    {'Comparison': 'EQUALS', 'Value': 'CRITICAL'},
                    {'Comparison': 'EQUALS', 'Value': 'HIGH'}
                ]
            },
            MaxResults=50
        )
        return findings.get('Findings', [])
    except Exception as e:
        print(f"Error retrieving Security Hub findings: {str(e)}")
        return []

def get_config_compliance():
    """Retrieve AWS Config compliance status."""
    if not ENABLE_CONFIG:
        return []
    
    try:
        rules = config_client.describe_config_rules()
        compliance = []
        for rule in rules.get('ConfigRules', []):
            rule_compliance = config_client.get_compliance_details_by_config_rule(
                ConfigRuleName=rule['ConfigRuleName']
            )
            if rule_compliance.get('EvaluationResults'):
                compliance.append({
                    'rule_name': rule['ConfigRuleName'],
                    'compliance': rule_compliance['EvaluationResults'][0]['ComplianceType']
                })
        return compliance
    except Exception as e:
        print(f"Error retrieving Config compliance: {str(e)}")
        return []

def format_event_message(detail):
    """Format a detailed Slack message based on the event."""
    event_name = detail.get("eventName", "Unknown Event")
    error_code = detail.get("errorCode", "N/A")
    event_source = detail.get("eventSource", "Unknown Source")
    user_identity = detail.get("userIdentity", {})
    username = safe_get(user_identity, "sessionContext", "sessionIssuer", "userName") or "Unknown Username"
    principal_id = user_identity.get("principalId", "Unknown Principal ID")
    account_id = user_identity.get("accountId", "Unknown Account ID")
    arn = user_identity.get("arn", "Unknown ARN")
    user_type = user_identity.get("type", "Unknown User Type")
    mfa_authenticated = safe_get(user_identity, "sessionContext", "attributes", "mfaAuthenticated") or "false"
    source_ip = detail.get("sourceIPAddress", "Unknown Source IP")
    user_agent = detail.get("userAgent", "Unknown User-Agent")
    region = detail.get("awsRegion", "Unknown Region")
    target_hostname = safe_get(detail, "tlsDetails", "clientProvidedHostHeader") or event_source
    event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())

    # Additional fields specific to IAM events
    console_login_result = safe_get(detail, "responseElements", "ConsoleLogin") or "N/A"
    mfa_used = safe_get(detail, "additionalEventData", "MFAUsed") or "Unknown"

    # Safely handle request parameters
    request_parameters = detail.get("requestParameters", {})
    additional_event_details = (
        json.dumps(request_parameters, indent=2) if request_parameters else "No additional details provided."
    )

    # Check for potential security risks
    security_risks = []
    if not mfa_authenticated.lower() == "true":
        security_risks.append("⚠️ MFA not used for authentication")
    if user_type == "Root":
        security_risks.append("⚠️ Root account activity detected")
    if error_code != "N/A":
        security_risks.append(f"⚠️ Action denied with error code: {error_code}")
    if "password" in str(request_parameters).lower():
        security_risks.append("⚠️ Password-related activity detected")

    message = (
        f"*Alert Details - {ACCOUNT_NAME} ({account_id})*\n"
        f"* **Event Name:** {event_name}\n"
        f"* **Action Result:** {'Action Allowed' if error_code == 'N/A' else f'Action Denied: {error_code}'}\n"
        f"* **Event Source:** {event_source}\n"
        f"* **Source_IP:** {source_ip}\n"
        f"* **Target Hostname:** {target_hostname}\n"
        f"* **Username:** {username}\n"
        f"* **User Type:** {user_type}\n"
        f"* **Zone:** {region}\n"
        f"* **Principal ID:** {principal_id}\n"
        f"* **MFA Authenticated:** {mfa_authenticated}\n"
        f"* **ARN:** {arn}\n"
        f"* **User-Agent:** {user_agent}\n"
        f"* **Console Login Result:** {console_login_result}\n"
        f"* **MFA Used:** {mfa_used}\n"
        f"* **Event Time:** {event_time}\n"
    )

    if security_risks:
        message += "\n*Security Risks Detected:*\n" + "\n".join(security_risks)

    if additional_event_details:
        message += f"\n*Additional Event Details:*\n```{additional_event_details}```"

    return message

def get_ecs_security_events():
    """Retrieve ECS security-related events."""
    if not ENABLE_ECS:
        return []
    
    try:
        events = []
        clusters = ecs_client.list_clusters()
        
        for cluster_arn in clusters.get('clusterArns', []):
            # Get cluster details
            cluster_details = ecs_client.describe_clusters(clusters=[cluster_arn])
            if not cluster_details.get('clusters'):
                continue
                
            cluster = cluster_details['clusters'][0]
            
            # Check for security-related issues
            if cluster.get('status') != 'ACTIVE':
                events.append({
                    'type': 'ECS_CLUSTER_STATUS',
                    'severity': 'HIGH',
                    'cluster': cluster.get('clusterName'),
                    'status': cluster.get('status'),
                    'description': f"ECS cluster {cluster.get('clusterName')} is not in ACTIVE status"
                })
            
            # Get task definitions
            task_defs = ecs_client.list_task_definitions()
            for task_def_arn in task_defs.get('taskDefinitionArns', []):
                task_def = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
                if not task_def.get('taskDefinition'):
                    continue
                    
                # Check for privileged containers
                for container_def in task_def['taskDefinition'].get('containerDefinitions', []):
                    if container_def.get('privileged'):
                        events.append({
                            'type': 'ECS_PRIVILEGED_CONTAINER',
                            'severity': 'HIGH',
                            'cluster': cluster.get('clusterName'),
                            'task_definition': task_def_arn,
                            'container': container_def.get('name'),
                            'description': f"Privileged container detected in task definition {task_def_arn}"
                        })
        
        return events
    except Exception as e:
        print(f"Error retrieving ECS security events: {str(e)}")
        return []

def get_eks_security_events():
    """Retrieve EKS security-related events."""
    if not ENABLE_EKS:
        return []
    
    try:
        events = []
        clusters = eks_client.list_clusters()
        
        for cluster_name in clusters.get('clusters', []):
            # Get cluster details
            cluster_details = eks_client.describe_cluster(name=cluster_name)
            if not cluster_details.get('cluster'):
                continue
                
            cluster = cluster_details['cluster']
            
            # Check for security-related issues
            if cluster.get('status') != 'ACTIVE':
                events.append({
                    'type': 'EKS_CLUSTER_STATUS',
                    'severity': 'HIGH',
                    'cluster': cluster_name,
                    'status': cluster.get('status'),
                    'description': f"EKS cluster {cluster_name} is not in ACTIVE status"
                })
            
            # Check for logging configuration
            if not cluster.get('logging', {}).get('clusterLogging', []):
                events.append({
                    'type': 'EKS_LOGGING_DISABLED',
                    'severity': 'MEDIUM',
                    'cluster': cluster_name,
                    'description': f"Logging is not enabled for EKS cluster {cluster_name}"
                })
            
            # Check for public access
            if cluster.get('resourcesVpcConfig', {}).get('endpointPublicAccess'):
                events.append({
                    'type': 'EKS_PUBLIC_ACCESS',
                    'severity': 'HIGH',
                    'cluster': cluster_name,
                    'description': f"Public access is enabled for EKS cluster {cluster_name}"
                })
        
        return events
    except Exception as e:
        print(f"Error retrieving EKS security events: {str(e)}")
        return []

def lambda_handler(event, context):
    """Process the event and send notifications to Slack."""
    try:
        whitelisted_arns = get_whitelisted_arns()
        print(f"Loaded {len(whitelisted_arns)} whitelisted ARNs: {whitelisted_arns}")

        # Dictionary to group events by resource and action
        event_groups = defaultdict(list)

        # Process CloudWatch Events
        for record in event["Records"]:
            try:
                sqs_body = json.loads(record["body"])
                detail = sqs_body.get("detail", {})

                # Extract and check ARN
                event_arn = safe_get(detail, "userIdentity", "arn") or "Unknown ARN"
                if is_whitelisted(event_arn):
                    print(f"Skipping whitelisted ARN: {event_arn}")
                    continue

                # Group events by resource and action
                event_name = detail.get("eventName", "Unknown Event")
                resource_arn = detail.get("resources", [{}])[0].get("ARN", "Unknown Resource")
                group_key = f"{event_name}:{resource_arn}"
                event_groups[group_key].append(detail)

            except Exception as e:
                print(f"Error processing record: {str(e)}")
                continue

        # Process grouped events
        for group_key, details in event_groups.items():
            if len(details) > 1:
                # Aggregate multiple events into a single message
                event_name = details[0].get("eventName", "Unknown Event")
                resource_arn = details[0].get("resources", [{}])[0].get("ARN", "Unknown Resource")
                message = (
                    f"*Aggregated Alert Details - {ACCOUNT_NAME}*\n"
                    f"* **Event Name:** {event_name}\n"
                    f"* **Resource ARN:** {resource_arn}\n"
                    f"* **Number of Events:** {len(details)}\n"
                )

                # Add details for each event
                for i, detail in enumerate(details, 1):
                    message += f"\n*Event {i}:*\n{format_event_message(detail)}"

                send_to_slack(message, is_critical_event(event_name))
            else:
                # Send a single message for non-grouped events
                message = format_event_message(details[0])
                send_to_slack(message, is_critical_event(event_name))

        # Process optional security service findings if enabled
        if ENABLE_GUARDDUTY:
            guardduty_findings = get_guardduty_findings()
            if guardduty_findings:
                message = f"*GuardDuty Findings - {ACCOUNT_NAME}*\n"
                for finding_id in guardduty_findings:
                    finding = guardduty_client.get_findings(
                        DetectorId=guardduty_client.list_detectors()['DetectorIds'][0],
                        FindingIds=[finding_id]
                    )
                    if finding.get('Findings'):
                        finding_details = finding['Findings'][0]
                        message += f"\n*Finding ID:* {finding_id}\n"
                        message += f"*Severity:* {finding_details.get('Severity', 'Unknown')}\n"
                        message += f"*Type:* {finding_details.get('Type', 'Unknown')}\n"
                        message += f"*Description:* {finding_details.get('Description', 'No description')}\n"
                send_to_slack(message, True)

        if ENABLE_SECURITYHUB:
            securityhub_findings = get_securityhub_findings()
            if securityhub_findings:
                message = f"*Security Hub Findings - {ACCOUNT_NAME}*\n"
                for finding in securityhub_findings:
                    message += f"\n*Finding ID:* {finding.get('Id', 'Unknown')}\n"
                    message += f"*Severity:* {finding.get('Severity', {}).get('Label', 'Unknown')}\n"
                    message += f"*Title:* {finding.get('Title', 'Unknown')}\n"
                    message += f"*Description:* {finding.get('Description', 'No description')}\n"
                send_to_slack(message, True)

        if ENABLE_CONFIG:
            config_compliance = get_config_compliance()
            if config_compliance:
                message = f"*AWS Config Compliance Status - {ACCOUNT_NAME}*\n"
                for rule in config_compliance:
                    message += f"\n*Rule:* {rule['rule_name']}\n"
                    message += f"*Compliance:* {rule['compliance']}\n"
                send_to_slack(message)

        # Process container security events
        ecs_events = get_ecs_security_events()
        if ecs_events:
            message = f"*ECS Security Events - {ACCOUNT_NAME}*\n"
            for event in ecs_events:
                message += f"\n*Type:* {event['type']}\n"
                message += f"*Severity:* {event['severity']}\n"
                message += f"*Cluster:* {event.get('cluster', 'N/A')}\n"
                message += f"*Description:* {event['description']}\n"
            send_to_slack(message, any(event['severity'] == 'HIGH' for event in ecs_events))

        eks_events = get_eks_security_events()
        if eks_events:
            message = f"*EKS Security Events - {ACCOUNT_NAME}*\n"
            for event in eks_events:
                message += f"\n*Type:* {event['type']}\n"
                message += f"*Severity:* {event['severity']}\n"
                message += f"*Cluster:* {event.get('cluster', 'N/A')}\n"
                message += f"*Description:* {event['description']}\n"
            send_to_slack(message, any(event['severity'] == 'HIGH' for event in eks_events))

    except Exception as e:
        print(f"Error processing event: {e}")
        send_to_slack(f"*Error in Lambda Function*\n{str(e)}")

    return {"statusCode": 200, "body": "Event processed successfully"}
