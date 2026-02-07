"""CloudTrail security check."""
import logging

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get CloudTrail security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        ct = clients.get("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            events.append({
                "severity": "CRITICAL",
                "description": "CRITICAL: No CloudTrail trails configured in this region",
            })
        else:
            for trail in trails:
                trail_name = trail.get("Name")
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if not status.get("IsLogging"):
                    events.append({
                        "severity": "CRITICAL",
                        "description": f"CRITICAL: CloudTrail {trail_name} is not logging",
                    })

                if not trail.get("IsMultiRegionTrail"):
                    events.append({
                        "severity": "HIGH",
                        "description": f"CloudTrail {trail_name} is not multi-region",
                    })

                if not trail.get("LogFileValidationEnabled"):
                    events.append({
                        "severity": "HIGH",
                        "description": f"CloudTrail {trail_name} does not have log file validation",
                    })
    except Exception as e:
        logger.error(f"CloudTrail check error: {e}")
    return events
