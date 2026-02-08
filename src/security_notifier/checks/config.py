"""AWS Config security check."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config_obj, clients):
    """Get AWS Config compliance issues.

    Args:
        config_obj: Configuration object
        clients: ClientFactory instance

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        config = clients.get("config")

        # Check if Config is enabled
        try:
            recorders = config.describe_configuration_recorders()
            recorder_list = recorders.get("ConfigurationRecorders", [])

            if not recorder_list:
                events.append({
                    "severity": "HIGH",
                    "description": "AWS Config is not enabled in this region",
                })
                return events

            # Check if recorder is recording
            for recorder in recorder_list:
                recorder_name = recorder.get("name")
                status = config.describe_configuration_recorder_status(
                    ConfigurationRecorderNames=[recorder_name]
                )
                for status_obj in status.get("ConfigurationRecordersStatus", []):
                    if not status_obj.get("recording", False):
                        events.append({
                            "severity": "HIGH",
                            "description": f"AWS Config recorder {recorder_name} is not recording",
                        })

        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchConfigurationRecorderException":
                events.append({
                    "severity": "HIGH",
                    "description": "AWS Config is not configured in this region",
                })
                return events

        # Check for non-compliant resources
        try:
            compliance_summary = config.describe_compliance_by_config_rule()
            rules = compliance_summary.get("ComplianceByConfigRules", [])

            non_compliant_count = 0
            for rule in rules:
                compliance = rule.get("Compliance", {})
                if compliance.get("ComplianceType") == "NON_COMPLIANT":
                    non_compliant_count += 1

            if non_compliant_count > 0:
                events.append({
                    "severity": "MEDIUM",
                    "description": f"AWS Config: {non_compliant_count} config rules are non-compliant",
                })

            # List specific non-compliant rules (top 5)
            for rule in rules[:5]:
                rule_name = rule.get("ConfigRuleName", "Unknown")
                compliance = rule.get("Compliance", {})
                if compliance.get("ComplianceType") == "NON_COMPLIANT":
                    events.append({
                        "severity": "LOW",
                        "description": f"Config rule '{rule_name}' is non-compliant",
                    })

        except ClientError as e:
            logger.debug(f"AWS Config compliance check error: {e}")

        # Check delivery channel
        try:
            delivery_channels = config.describe_delivery_channels()
            if not delivery_channels.get("DeliveryChannels", []):
                events.append({
                    "severity": "MEDIUM",
                    "description": "AWS Config has no delivery channel configured",
                })
        except ClientError:
            pass

    except Exception as e:
        logger.error(f"AWS Config check error: {e}")
    return events

