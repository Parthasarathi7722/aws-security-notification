"""Main Lambda handler with registry-based check orchestration."""
import json
import logging
import traceback
from collections import defaultdict

from .config import Config, safe_get, is_whitelisted, is_critical_event
from .clients import ClientFactory
from .slack import SlackNotifier
from .formatter import format_event_message
from .checks import REGISTRY

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def lambda_handler(event, context):
    """Main Lambda handler."""
    config = Config()
    clients = ClientFactory()
    notifier = SlackNotifier(config)

    request_id = context.request_id if context else "local"
    logger.info(f"Processing {len(event.get('Records', []))} records - {request_id}")

    try:
        event_groups = defaultdict(list)

        # Process SQS messages
        for record in event.get("Records", []):
            try:
                sqs_body = json.loads(record["body"])
                detail = sqs_body.get("detail", {})

                # Check whitelist
                event_arn = safe_get(detail, "userIdentity", "arn") or "Unknown"
                if is_whitelisted(config, event_arn):
                    continue

                # Group events
                event_name = detail.get("eventName", "Unknown")
                resource_arn = detail.get("resources", [{}])[0].get("ARN", "Unknown")
                event_groups[f"{event_name}:{resource_arn}"].append(detail)

            except Exception as e:
                logger.error(f"Record error: {e}")
                continue

        # Send notifications for grouped events
        for group_key, details in event_groups.items():
            try:
                event_name = details[0].get("eventName")
                is_crit = is_critical_event(config, event_name)

                if len(details) > 1:
                    msg = (
                        f"*Aggregated Alert - {config.account_name}*\n"
                        f"*Event:* {event_name}\n"
                        f"*Count:* {len(details)} events\n\n"
                    )
                    for i, detail in enumerate(details[:3], 1):
                        msg += f"*Event {i}:*\n{format_event_message(config, detail)}\n"
                    if len(details) > 3:
                        msg += f"\n...and {len(details) - 3} more"
                else:
                    msg = format_event_message(config, details[0])

                notifier.send(msg, is_crit)
            except Exception as e:
                logger.error(f"Group error: {e}")

        # Registry-based service checks
        for flag_attr, label, check_module in REGISTRY:
            if not getattr(config, flag_attr, False):
                continue
            try:
                events = check_module.run(config, clients)
                if events:
                    has_critical = any(e["severity"] == "CRITICAL" for e in events)
                    msg = f"*{label} - {config.account_name}*\n"
                    for evt in events[:10]:
                        msg += f"[{evt['severity']}] {evt['description']}\n"
                    notifier.send(msg, has_critical)
            except Exception as e:
                logger.error(f"{label} check error: {e}")

        logger.info(f"Complete - {request_id}")
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Success"}),
        }

    except Exception as e:
        logger.error(f"Handler error: {e}\n{traceback.format_exc()}")

        try:
            notifier.send(f"*Error - {config.account_name}*\n{e}", True)
        except Exception as e2:
            logger.error(f"Error reporting failure: {e2}")

        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
