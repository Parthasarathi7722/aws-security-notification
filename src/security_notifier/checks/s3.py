"""S3 security check."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get S3 security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        s3 = clients.get("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets[:50]:
            bucket_name = bucket["Name"]
            try:
                # Check public access block
                try:
                    public_block = s3.get_public_access_block(Bucket=bucket_name)
                    config_data = public_block.get("PublicAccessBlockConfiguration", {})
                    if not all([
                        config_data.get("BlockPublicAcls"),
                        config_data.get("IgnorePublicAcls"),
                        config_data.get("BlockPublicPolicy"),
                        config_data.get("RestrictPublicBuckets"),
                    ]):
                        events.append({
                            "severity": "CRITICAL",
                            "description": f"CRITICAL: Bucket {bucket_name} does not block all public access",
                        })
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                        events.append({
                            "severity": "CRITICAL",
                            "description": f"CRITICAL: Bucket {bucket_name} has no public access block configured",
                        })

                # Check encryption
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == "ServerSideEncryptionConfigurationNotFoundError":
                        events.append({
                            "severity": "HIGH",
                            "description": f"Bucket {bucket_name} has no encryption enabled",
                        })

                # Check versioning
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") != "Enabled":
                    events.append({
                        "severity": "MEDIUM",
                        "description": f"Bucket {bucket_name} does not have versioning enabled",
                    })
            except Exception as e:
                logger.debug(f"Error checking bucket {bucket_name}: {e}")
    except Exception as e:
        logger.error(f"S3 check error: {e}")
    return events
