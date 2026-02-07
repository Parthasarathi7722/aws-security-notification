"""Lambda security check."""
import json
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get Lambda security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        lam = clients.get("lambda")
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate(MaxItems=100):
            for func in page.get("Functions", []):
                func_name = func.get("FunctionName")

                try:
                    policy = lam.get_policy(FunctionName=func_name)
                    policy_doc = json.loads(policy["Policy"])
                    for statement in policy_doc.get("Statement", []):
                        principal = statement.get("Principal")
                        if principal == "*" or (
                            isinstance(principal, dict) and principal.get("AWS") == "*"
                        ):
                            events.append({
                                "severity": "CRITICAL",
                                "description": f"CRITICAL: Lambda {func_name} has public policy allowing anyone to invoke",
                            })
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                        logger.debug(f"Lambda policy check error for {func_name}: {e}")

                if func.get("Environment", {}).get("Variables"):
                    if not func.get("KMSKeyArn"):
                        events.append({
                            "severity": "HIGH",
                            "description": f"Lambda {func_name} has environment variables but no KMS encryption",
                        })

                if func.get("VpcConfig") and func.get("VpcConfig", {}).get("VpcId"):
                    if not func.get("VpcConfig", {}).get("SecurityGroupIds"):
                        events.append({
                            "severity": "MEDIUM",
                            "description": f"Lambda {func_name} in VPC but no security groups",
                        })
    except Exception as e:
        logger.error(f"Lambda check error: {e}")
    return events
