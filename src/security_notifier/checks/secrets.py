"""Secrets Manager security check."""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get Secrets Manager security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        sm = clients.get("secretsmanager")
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate(MaxResults=100):
            for secret in page.get("SecretList", []):
                secret_name = secret.get("Name")

                if not secret.get("RotationEnabled"):
                    events.append({
                        "severity": "MEDIUM",
                        "description": f"Secret {secret_name} does not have automatic rotation enabled",
                    })

                if secret.get("LastAccessedDate"):
                    days_since_access = (
                        datetime.now(timezone.utc) - secret["LastAccessedDate"]
                    ).days
                    if days_since_access > 90:
                        events.append({
                            "severity": "LOW",
                            "description": f"Secret {secret_name} has not been accessed in {days_since_access} days",
                        })
    except Exception as e:
        logger.error(f"Secrets Manager check error: {e}")
    return events
