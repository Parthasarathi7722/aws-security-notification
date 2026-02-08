"""EKS security check."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get EKS security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        eks = clients.get("eks")

        # List clusters
        clusters_response = eks.list_clusters(maxResults=100)
        cluster_names = clusters_response.get("clusters", [])

        for cluster_name in cluster_names:
            try:
                # Describe cluster
                cluster = eks.describe_cluster(name=cluster_name).get("cluster", {})

                # Check public endpoint access
                endpoint_access = cluster.get("resourcesVpcConfig", {})
                if endpoint_access.get("endpointPublicAccess", False):
                    public_access_cidrs = endpoint_access.get("publicAccessCidrs", [])
                    if "0.0.0.0/0" in public_access_cidrs:
                        events.append({
                            "severity": "HIGH",
                            "description": f"EKS cluster {cluster_name} has public endpoint access from 0.0.0.0/0",
                        })

                # Check if endpoint private access is disabled
                if not endpoint_access.get("endpointPrivateAccess", False):
                    events.append({
                        "severity": "MEDIUM",
                        "description": f"EKS cluster {cluster_name} does not have private endpoint access enabled",
                    })

                # Check cluster logging
                logging_config = cluster.get("logging", {}).get("clusterLogging", [])
                if not logging_config:
                    events.append({
                        "severity": "MEDIUM",
                        "description": f"EKS cluster {cluster_name} does not have any control plane logging enabled",
                    })
                else:
                    # Check if all log types are enabled
                    enabled_types = []
                    for log_setup in logging_config:
                        if log_setup.get("enabled", False):
                            enabled_types.extend(log_setup.get("types", []))

                    recommended_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
                    missing_types = [t for t in recommended_types if t not in enabled_types]
                    if missing_types:
                        events.append({
                            "severity": "LOW",
                            "description": f"EKS cluster {cluster_name} is missing log types: {', '.join(missing_types)}",
                        })

                # Check encryption
                encryption = cluster.get("encryptionConfig", [])
                if not encryption:
                    events.append({
                        "severity": "HIGH",
                        "description": f"EKS cluster {cluster_name} does not have secrets encryption enabled",
                    })

                # Check cluster version (warn if older than 2 versions behind latest)
                cluster_version = cluster.get("version", "")
                try:
                    version_number = float(cluster_version)
                    # As of 2026, let's assume 1.30 is latest, warn if < 1.28
                    if version_number < 1.28:
                        events.append({
                            "severity": "MEDIUM",
                            "description": f"EKS cluster {cluster_name} is running an outdated version {cluster_version}",
                        })
                except ValueError:
                    pass

            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    logger.debug(f"EKS check error for cluster {cluster_name}: {e}")
            except Exception as e:
                logger.debug(f"EKS check error for cluster {cluster_name}: {e}")

    except Exception as e:
        logger.error(f"EKS check error: {e}")
    return events

