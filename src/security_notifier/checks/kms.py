"""KMS security check."""
import logging

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get KMS security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        kms = clients.get("kms")
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate(Limit=100):
            for key in page.get("Keys", []):
                key_id = key["KeyId"]
                try:
                    metadata = kms.describe_key(KeyId=key_id)
                    key_data = metadata["KeyMetadata"]

                    # Skip AWS managed keys
                    if key_data.get("KeyManager") == "AWS":
                        continue

                    if key_data.get("KeyState") == "Enabled":
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        if not rotation.get("KeyRotationEnabled"):
                            events.append({
                                "severity": "MEDIUM",
                                "description": f"KMS key {key_data.get('Arn', key_id)} does not have automatic rotation enabled",
                            })
                except Exception as e:
                    logger.debug(f"KMS key check error for {key_id}: {e}")
    except Exception as e:
        logger.error(f"KMS check error: {e}")
    return events
