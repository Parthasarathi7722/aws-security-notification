"""Security check registry - Core checks only."""
from . import guardduty, securityhub, iam, cloudtrail

# (config_flag_attr, label, module)
REGISTRY = [
    ("enable_guardduty", "GuardDuty", guardduty),
    ("enable_securityhub", "Security Hub", securityhub),
    ("enable_iam", "IAM Security", iam),
    ("enable_cloudtrail", "CloudTrail Security", cloudtrail),
]
