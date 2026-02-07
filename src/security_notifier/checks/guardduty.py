"""GuardDuty security check."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get high-severity GuardDuty findings.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        gd = clients.get("guardduty")
        detectors = gd.list_detectors()
        if not detectors.get("DetectorIds"):
            return events
        findings = gd.list_findings(
            DetectorId=detectors["DetectorIds"][0],
            FindingCriteria={"Criterion": {"severity": {"Gte": 4}}},
            MaxResults=50,
        )
        finding_ids = findings.get("FindingIds", [])
        if finding_ids:
            events.append({
                "severity": "CRITICAL",
                "description": f"{len(finding_ids)} high-severity findings",
            })
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "BadRequestException":
            logger.warning(f"GuardDuty error: {e}")
    except Exception as e:
        logger.error(f"GuardDuty error: {e}")
    return events
