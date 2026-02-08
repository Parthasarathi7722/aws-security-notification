"""EC2 security check."""
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get EC2 security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        ec2 = clients.get("ec2")

        # Check security groups with overly permissive rules
        security_groups = ec2.describe_security_groups(MaxResults=100)
        for sg in security_groups.get("SecurityGroups", []):
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "Unknown")

            # Check for 0.0.0.0/0 or ::/0 with sensitive ports
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr in ["0.0.0.0/0"]:
                        # Check for sensitive ports
                        if from_port <= 22 <= to_port:
                            events.append({
                                "severity": "CRITICAL",
                                "description": f"Security group {sg_name} ({sg_id}) allows SSH (22) from 0.0.0.0/0",
                            })
                        elif from_port <= 3389 <= to_port:
                            events.append({
                                "severity": "CRITICAL",
                                "description": f"Security group {sg_name} ({sg_id}) allows RDP (3389) from 0.0.0.0/0",
                            })
                        elif from_port == 0 and to_port == 65535:
                            events.append({
                                "severity": "CRITICAL",
                                "description": f"Security group {sg_name} ({sg_id}) allows ALL traffic from 0.0.0.0/0",
                            })

                for ipv6_range in rule.get("Ipv6Ranges", []):
                    cidr = ipv6_range.get("CidrIpv6", "")
                    if cidr == "::/0":
                        if from_port <= 22 <= to_port:
                            events.append({
                                "severity": "CRITICAL",
                                "description": f"Security group {sg_name} ({sg_id}) allows SSH (22) from ::/0",
                            })
                        elif from_port <= 3389 <= to_port:
                            events.append({
                                "severity": "CRITICAL",
                                "description": f"Security group {sg_name} ({sg_id}) allows RDP (3389) from ::/0",
                            })

        # Check for instances without IMDSv2
        instances = ec2.describe_instances(MaxResults=100)
        for reservation in instances.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId")
                state = instance.get("State", {}).get("Name")

                if state in ["running", "stopped"]:
                    metadata_options = instance.get("MetadataOptions", {})
                    http_tokens = metadata_options.get("HttpTokens", "optional")
                    if http_tokens != "required":
                        events.append({
                            "severity": "MEDIUM",
                            "description": f"EC2 instance {instance_id} does not require IMDSv2 (metadata service v2)",
                        })

        # Check for unencrypted EBS volumes
        volumes = ec2.describe_volumes(MaxResults=100)
        for volume in volumes.get("Volumes", []):
            volume_id = volume.get("VolumeId")
            encrypted = volume.get("Encrypted", False)
            state = volume.get("State")

            if not encrypted and state == "in-use":
                events.append({
                    "severity": "HIGH",
                    "description": f"EBS volume {volume_id} is not encrypted",
                })

    except ClientError as e:
        logger.warning(f"EC2 check error: {e}")
    except Exception as e:
        logger.error(f"EC2 check error: {e}")
    return events

