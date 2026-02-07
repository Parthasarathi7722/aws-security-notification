"""Security check registry."""
from . import (
    guardduty,
    securityhub,
    config_compliance,
    ecs,
    eks,
    rds,
    lambda_check,
    iam,
    s3,
    cloudtrail,
    kms,
    secrets,
)

# (config_flag_attr, label, module)
REGISTRY = [
    ("enable_guardduty", "GuardDuty", guardduty),
    ("enable_securityhub", "Security Hub", securityhub),
    ("enable_config", "Config", config_compliance),
    ("enable_ecs", "ECS Security", ecs),
    ("enable_eks", "EKS Security", eks),
    ("enable_rds", "RDS Security", rds),
    ("enable_lambda_checks", "Lambda Security", lambda_check),
    ("enable_iam_checks", "IAM Security", iam),
    ("enable_s3_checks", "S3 Security", s3),
    ("enable_cloudtrail_checks", "CloudTrail Security", cloudtrail),
    ("enable_kms_checks", "KMS Security", kms),
    ("enable_secrets_checks", "Secrets Manager", secrets),
]
