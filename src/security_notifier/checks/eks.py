"""EKS security check."""
import logging

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get EKS security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        eks = clients.get("eks")
        clusters = eks.list_clusters(maxResults=10)
        for cluster_name in clusters.get("clusters", []):
            try:
                details = eks.describe_cluster(name=cluster_name)
                cluster = details["cluster"]
                if cluster.get("status") != "ACTIVE":
                    events.append({
                        "severity": "HIGH",
                        "description": f"Cluster {cluster_name} is {cluster.get('status')}",
                    })
                if cluster.get("resourcesVpcConfig", {}).get("endpointPublicAccess"):
                    events.append({
                        "severity": "MEDIUM",
                        "description": f"Public access enabled for {cluster_name}",
                    })
            except Exception as e:
                logger.debug(f"EKS cluster check error: {e}")
                continue
    except Exception as e:
        logger.error(f"EKS check error: {e}")
    return events
