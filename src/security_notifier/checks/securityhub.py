"""Security Hub check."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get critical/high Security Hub findings.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        sh = clients.get("securityhub")
        findings = sh.get_findings(
            Filters={
                "SeverityLabel": [
                    {"Comparison": "EQUALS", "Value": "CRITICAL"},
                    {"Comparison": "EQUALS", "Value": "HIGH"},
                ]
            },
            MaxResults=50,
        )
        result = findings.get("Findings", [])
        if result:
            events.append({
                "severity": "CRITICAL",
                "description": f"{len(result)} critical/high findings",
            })
    except ClientError:
        pass
    except Exception as e:
        logger.error(f"Security Hub error: {e}")
    return events
