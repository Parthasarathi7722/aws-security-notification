"""IAM security check."""
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get IAM security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        iam = clients.get("iam")

        # Check for users without MFA
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate(MaxItems=100):
            users.extend(page.get("Users", []))

        for user in users:
            username = user.get("UserName")
            try:
                mfa = iam.list_mfa_devices(UserName=username)
                if not mfa.get("MFADevices"):
                    try:
                        iam.get_login_profile(UserName=username)
                        events.append({
                            "severity": "HIGH",
                            "description": f"User {username} has console access but no MFA enabled",
                        })
                    except ClientError:
                        pass  # No console access
            except Exception as e:
                logger.debug(f"IAM MFA check error for {username}: {e}")

        # Check for overly permissive policies
        policies = iam.list_policies(Scope="Local", MaxItems=50)
        for policy in policies.get("Policies", []):
            try:
                policy_version = iam.get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=policy["DefaultVersionId"],
                )
                doc = policy_version["PolicyVersion"]["Document"]
                for statement in doc.get("Statement", []):
                    if statement.get("Effect") == "Allow":
                        actions = statement.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if "*" in actions or "iam:*" in actions:
                            resources = statement.get("Resource", [])
                            if isinstance(resources, str):
                                resources = [resources]
                            if "*" in resources:
                                events.append({
                                    "severity": "HIGH",
                                    "description": f"Policy {policy['PolicyName']} grants admin access (*:* on *)",
                                })
            except Exception as e:
                logger.debug(f"IAM policy check error: {e}")

        # Check for access keys older than 90 days
        for user in users:
            username = user.get("UserName")
            try:
                keys = iam.list_access_keys(UserName=username)
                for key in keys.get("AccessKeyMetadata", []):
                    if key.get("Status") == "Active":
                        age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                        if age_days > 90:
                            events.append({
                                "severity": "MEDIUM",
                                "description": f"Access key for {username} is {age_days} days old (>90 days)",
                            })
            except Exception as e:
                logger.debug(f"IAM access key check error for {username}: {e}")
    except Exception as e:
        logger.error(f"IAM check error: {e}")
    return events
