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

        # List buckets (limit to 100 for performance)
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])[:100]

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                # Check public access block
                try:
                    public_block = s3.get_public_access_block(Bucket=bucket_name)
                    config_block = public_block.get("PublicAccessBlockConfiguration", {})
                    if not all([
                        config_block.get("BlockPublicAcls"),
                        config_block.get("BlockPublicPolicy"),
                        config_block.get("IgnorePublicAcls"),
                        config_block.get("RestrictPublicBuckets")
                    ]):
                        events.append({
                            "severity": "HIGH",
                            "description": f"S3 bucket {bucket_name} does not have all public access blocks enabled",
                        })
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                        events.append({
                            "severity": "HIGH",
                            "description": f"S3 bucket {bucket_name} has no public access block configuration",
                        })

                # Check bucket encryption
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == "ServerSideEncryptionConfigurationNotFoundError":
                        events.append({
                            "severity": "MEDIUM",
                            "description": f"S3 bucket {bucket_name} does not have default encryption enabled",
                        })

                # Check bucket versioning
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") != "Enabled":
                    events.append({
                        "severity": "MEDIUM",
                        "description": f"S3 bucket {bucket_name} does not have versioning enabled",
                    })

                # Check bucket logging
                try:
                    logging_status = s3.get_bucket_logging(Bucket=bucket_name)
                    if "LoggingEnabled" not in logging_status:
                        events.append({
                            "severity": "LOW",
                            "description": f"S3 bucket {bucket_name} does not have access logging enabled",
                        })
                except ClientError:
                    pass

            except ClientError as e:
                if e.response.get("Error", {}).get("Code") not in ["NoSuchBucket", "AccessDenied"]:
                    logger.debug(f"S3 check error for {bucket_name}: {e}")
            except Exception as e:
                logger.debug(f"S3 check error for {bucket_name}: {e}")

    except Exception as e:
        logger.error(f"S3 check error: {e}")
    return events

