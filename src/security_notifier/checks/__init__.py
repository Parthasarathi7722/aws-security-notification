"""Security check registry - All available security checks."""
from . import guardduty, securityhub, iam, cloudtrail, s3, ec2, ecs, eks, config

# (config_flag_attr, label, module)
REGISTRY = [
    ("enable_guardduty", "GuardDuty", guardduty),
    ("enable_securityhub", "Security Hub", securityhub),
    ("enable_iam", "IAM Security", iam),
    ("enable_cloudtrail", "CloudTrail Security", cloudtrail),
    ("enable_s3", "S3 Security", s3),
    ("enable_ec2", "EC2 Security", ec2),
    ("enable_ecs", "ECS Security", ecs),
    ("enable_eks", "EKS Security", eks),
    ("enable_config", "AWS Config Compliance", config),
]
