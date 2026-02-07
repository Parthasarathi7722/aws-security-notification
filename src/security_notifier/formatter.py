"""Event message formatting for Slack notifications."""
import logging
from datetime import datetime, timezone

from .config import safe_get

logger = logging.getLogger(__name__)


def format_event_message(config, detail):
    """Format event details into Slack message."""
    try:
        event_name = detail.get("eventName", "Unknown")
        error_code = detail.get("errorCode", "N/A")
        user_identity = detail.get("userIdentity", {})
        username = (
            safe_get(user_identity, "sessionContext", "sessionIssuer", "userName")
            or safe_get(user_identity, "userName")
            or "Unknown"
        )
        account_id = user_identity.get("accountId", "Unknown")
        arn = user_identity.get("arn", "Unknown")
        user_type = user_identity.get("type", "Unknown")
        mfa = (
            safe_get(user_identity, "sessionContext", "attributes", "mfaAuthenticated")
            or "false"
        )
        source_ip = detail.get("sourceIPAddress", "Unknown")
        region = detail.get("awsRegion", "Unknown")
        event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())

        # Security risks
        risks = []
        if mfa.lower() != "true":
            risks.append("\u26a0\ufe0f No MFA")
        if user_type == "Root":
            risks.append("\u26a0\ufe0f Root account")
        if error_code != "N/A":
            risks.append(f"\u26a0\ufe0f Denied: {error_code}")

        msg = (
            f"*{config.account_name} ({account_id})*\n"
            f"*Event:* {event_name}\n"
            f"*User:* {username} ({user_type})\n"
            f"*Source IP:* {source_ip}\n"
            f"*Region:* {region}\n"
            f"*Time:* {event_time}\n"
        )

        if risks:
            msg += "*Risks:* " + ", ".join(risks) + "\n"

        return msg
    except Exception as e:
        return f"*{config.account_name}*\nError formatting message: {e}"
