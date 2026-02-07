"""CloudWatch metrics publishing."""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def new_metrics():
    """Create a fresh metrics dict."""
    return {
        "events_processed": 0,
        "events_filtered": 0,
        "notifications_sent": 0,
        "notifications_failed": 0,
        "errors": 0,
    }


def publish_metrics(clients, metrics):
    """Publish metrics to CloudWatch."""
    try:
        cw = clients.get("cloudwatch")
        cw.put_metric_data(
            Namespace="SecurityNotifications",
            MetricData=[
                {
                    "MetricName": k,
                    "Value": v,
                    "Unit": "Count",
                    "Timestamp": datetime.now(timezone.utc),
                }
                for k, v in metrics.items()
            ],
        )
        logger.info(f"Metrics: {metrics}")
    except Exception as e:
        logger.error(f"Metrics error: {e}")
