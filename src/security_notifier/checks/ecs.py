"""ECS security check."""
import logging

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get ECS security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        ecs = clients.get("ecs")
        clusters = ecs.list_clusters(maxResults=10)
        for cluster_arn in clusters.get("clusterArns", []):
            try:
                details = ecs.describe_clusters(clusters=[cluster_arn])
                cluster = details["clusters"][0]
                if cluster.get("status") != "ACTIVE":
                    events.append({
                        "severity": "HIGH",
                        "description": f"Cluster {cluster.get('clusterName')} is {cluster.get('status')}",
                    })
            except Exception as e:
                logger.debug(f"ECS cluster check error: {e}")
                continue
    except Exception as e:
        logger.error(f"ECS check error: {e}")
    return events
