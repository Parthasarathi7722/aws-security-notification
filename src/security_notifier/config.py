"""Configuration from environment variables."""
import os
import fnmatch


class Config:
    """Configuration from environment variables."""

    def __init__(self):
        self.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not self.slack_webhook_url:
            raise ValueError("SLACK_WEBHOOK_URL is required")

        self.account_name = os.getenv("ACCOUNT_NAME", "AWS Account")
        self.whitelist_resources = [
            x.strip() for x in os.getenv("WHITELIST_RESOURCES", "").split(",") if x.strip()
        ]
        self.critical_events = [
            x.strip() for x in os.getenv("CRITICAL_EVENTS", "").split(",") if x.strip()
        ]

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


def safe_get(dictionary, *keys):
    """Safely get nested dictionary value."""
    for key in keys:
        if dictionary is None or key not in dictionary:
            return None
        dictionary = dictionary[key]
    return dictionary


def is_whitelisted(config, event_arn):
    """Check if ARN matches whitelist (supports wildcards)."""
    if not event_arn or event_arn == "Unknown ARN":
        return False
    return any(fnmatch.fnmatch(event_arn, pattern) for pattern in config.whitelist_resources)


def is_critical_event(config, event_name):
    """Check if event is critical."""
    return event_name in config.critical_events if event_name else False
