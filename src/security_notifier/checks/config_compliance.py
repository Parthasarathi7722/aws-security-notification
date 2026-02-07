"""AWS Config compliance check."""
import logging

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get AWS Config compliance status.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        cfg = clients.get("config")
        rules = cfg.describe_config_rules()
        non_compliant = []
        for rule in rules.get("ConfigRules", []):
            try:
                result = cfg.get_compliance_details_by_config_rule(
                    ConfigRuleName=rule["ConfigRuleName"]
                )
                if result.get("EvaluationResults"):
                    compliance_type = result["EvaluationResults"][0]["ComplianceType"]
                    if compliance_type != "COMPLIANT":
                        non_compliant.append(rule["ConfigRuleName"])
            except Exception as e:
                logger.debug(f"Config rule check error: {e}")
                continue
        if non_compliant:
            events.append({
                "severity": "HIGH",
                "description": f"{len(non_compliant)} non-compliant rules",
            })
    except Exception as e:
        logger.error(f"Config compliance error: {e}")
    return events
