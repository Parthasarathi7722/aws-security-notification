"""ECS security check."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get ECS security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        ecs = clients.get("ecs")

        # List clusters
        clusters_response = ecs.list_clusters(maxResults=100)
        cluster_arns = clusters_response.get("clusterArns", [])

        for cluster_arn in cluster_arns:
            try:
                # List services in cluster
                services_response = ecs.list_services(cluster=cluster_arn, maxResults=100)
                service_arns = services_response.get("serviceArns", [])

                if service_arns:
                    # Describe services
                    services = ecs.describe_services(cluster=cluster_arn, services=service_arns)

                    for service in services.get("services", []):
                        service_name = service.get("serviceName")

                        # Check if service is not using secrets or SSM parameters
                        task_definition_arn = service.get("taskDefinition")
                        if task_definition_arn:
                            task_def = ecs.describe_task_definition(taskDefinition=task_definition_arn)
                            container_defs = task_def.get("taskDefinition", {}).get("containerDefinitions", [])

                            for container in container_defs:
                                container_name = container.get("name")

                                # Check for hardcoded environment variables (potential secrets)
                                env_vars = container.get("environment", [])
                                for env in env_vars:
                                    key = env.get("name", "")
                                    if any(keyword in key.upper() for keyword in ["PASSWORD", "SECRET", "KEY", "TOKEN"]):
                                        events.append({
                                            "severity": "HIGH",
                                            "description": f"ECS service {service_name} container {container_name} may have hardcoded secrets in environment variable {key}",
                                        })

                                # Check if running as privileged
                                if container.get("privileged", False):
                                    events.append({
                                        "severity": "HIGH",
                                        "description": f"ECS service {service_name} container {container_name} is running in privileged mode",
                                    })

                                # Check if running as root
                                if not container.get("user"):
                                    events.append({
                                        "severity": "MEDIUM",
                                        "description": f"ECS service {service_name} container {container_name} is running as root user",
                                    })

                        # Check network configuration for public IP assignment
                        network_config = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
                        if network_config.get("assignPublicIp") == "ENABLED":
                            events.append({
                                "severity": "MEDIUM",
                                "description": f"ECS service {service_name} has public IP assignment enabled",
                            })

            except ClientError as e:
                logger.debug(f"ECS check error for cluster {cluster_arn}: {e}")
            except Exception as e:
                logger.debug(f"ECS check error for cluster {cluster_arn}: {e}")

    except Exception as e:
        logger.error(f"ECS check error: {e}")
    return events

