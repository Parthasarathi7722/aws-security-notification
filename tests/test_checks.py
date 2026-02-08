"""Tests for security check modules."""
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from security_notifier.checks import guardduty, securityhub, iam, cloudtrail
from security_notifier.checks import s3 as s3_check
from security_notifier.checks import ec2 as ec2_check
from security_notifier.checks import ecs as ecs_check
from security_notifier.checks import eks as eks_check
from security_notifier.checks import config as config_check


def _mock_clients(service_returns):
    """Build a mock ClientFactory with pre-configured service responses."""
    mock = MagicMock()
    mocks = {}
    for svc, attrs in service_returns.items():
        svc_mock = MagicMock()
        for attr, val in attrs.items():
            if callable(val):
                getattr(svc_mock, attr).side_effect = val
            else:
                getattr(svc_mock, attr).return_value = val
        mocks[svc] = svc_mock
    mock.get = lambda name: mocks.get(name, MagicMock())
    return mock


def _config():
    """Create a minimal config-like object."""
    cfg = MagicMock()
    cfg.account_name = "TestAccount"
    return cfg


class TestGuardDuty:
    def test_no_detectors(self):
        clients = _mock_clients({"guardduty": {"list_detectors": {"DetectorIds": []}}})
        assert guardduty.run(_config(), clients) == []

    def test_findings_returned(self):
        clients = _mock_clients({
            "guardduty": {
                "list_detectors": {"DetectorIds": ["det-1"]},
                "list_findings": {"FindingIds": ["f1", "f2"]},
            }
        })
        result = guardduty.run(_config(), clients)
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"
        assert "2" in result[0]["description"]


class TestSecurityHub:
    def test_no_findings(self):
        clients = _mock_clients({"securityhub": {"get_findings": {"Findings": []}}})
        assert securityhub.run(_config(), clients) == []

    def test_findings_returned(self):
        clients = _mock_clients({
            "securityhub": {"get_findings": {"Findings": [{"id": "1"}, {"id": "2"}]}}
        })
        result = securityhub.run(_config(), clients)
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"


class TestIAM:
    def test_basic_iam_check(self):
        """Test IAM check runs without errors"""
        clients = _mock_clients({
            "iam": {
                "list_users": {"Users": []},
                "list_roles": {"Roles": []},
            }
        })
        result = iam.run(_config(), clients)
        assert isinstance(result, list)


class TestCloudTrail:
    def test_no_trails(self):
        clients = _mock_clients({
            "cloudtrail": {"describe_trails": {"trailList": []}}
        })
        result = cloudtrail.run(_config(), clients)
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"

    def test_not_logging(self):
        ct_mock = MagicMock()
        ct_mock.describe_trails.return_value = {
            "trailList": [{"Name": "t1", "TrailARN": "arn:trail", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]
        }
        ct_mock.get_trail_status.return_value = {"IsLogging": False}
        clients = MagicMock()
        clients.get = lambda name: ct_mock if name == "cloudtrail" else MagicMock()

        result = cloudtrail.run(_config(), clients)
        assert any(e["severity"] == "CRITICAL" for e in result)


class TestS3:
    def test_no_buckets(self):
        clients = _mock_clients({"s3": {"list_buckets": {"Buckets": []}}})
        assert s3_check.run(_config(), clients) == []

    def test_public_bucket(self):
        s3_mock = MagicMock()
        s3_mock.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
        s3_mock.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True
            }
        }
        clients = MagicMock()
        clients.get = lambda name: s3_mock if name == "s3" else MagicMock()

        result = s3_check.run(_config(), clients)
        assert any("public access" in e["description"].lower() for e in result)


class TestEC2:
    def test_open_security_group(self):
        ec2_mock = MagicMock()
        ec2_mock.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-123",
                "GroupName": "test-sg",
                "IpPermissions": [{
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            }]
        }
        ec2_mock.describe_instances.return_value = {"Reservations": []}
        ec2_mock.describe_volumes.return_value = {"Volumes": []}

        clients = MagicMock()
        clients.get = lambda name: ec2_mock if name == "ec2" else MagicMock()

        result = ec2_check.run(_config(), clients)
        assert any("SSH" in e["description"] for e in result)


class TestECS:
    def test_no_clusters(self):
        clients = _mock_clients({"ecs": {"list_clusters": {"clusterArns": []}}})
        assert ecs_check.run(_config(), clients) == []

    def test_privileged_container(self):
        ecs_mock = MagicMock()
        ecs_mock.list_clusters.return_value = {"clusterArns": ["arn:cluster"]}
        ecs_mock.list_services.return_value = {"serviceArns": ["arn:service"]}
        ecs_mock.describe_services.return_value = {
            "services": [{
                "serviceName": "test-service",
                "taskDefinition": "arn:task"
            }]
        }
        ecs_mock.describe_task_definition.return_value = {
            "taskDefinition": {
                "containerDefinitions": [{
                    "name": "test-container",
                    "privileged": True,
                    "environment": []
                }]
            }
        }

        clients = MagicMock()
        clients.get = lambda name: ecs_mock if name == "ecs" else MagicMock()

        result = ecs_check.run(_config(), clients)
        assert any("privileged" in e["description"].lower() for e in result)


class TestEKS:
    def test_no_clusters(self):
        clients = _mock_clients({"eks": {"list_clusters": {"clusters": []}}})
        assert eks_check.run(_config(), clients) == []

    def test_public_endpoint(self):
        eks_mock = MagicMock()
        eks_mock.list_clusters.return_value = {"clusters": ["test-cluster"]}
        eks_mock.describe_cluster.return_value = {
            "cluster": {
                "name": "test-cluster",
                "resourcesVpcConfig": {
                    "endpointPublicAccess": True,
                    "publicAccessCidrs": ["0.0.0.0/0"],
                    "endpointPrivateAccess": False
                },
                "logging": {"clusterLogging": []},
                "encryptionConfig": [],
                "version": "1.25"
            }
        }

        clients = MagicMock()
        clients.get = lambda name: eks_mock if name == "eks" else MagicMock()

        result = eks_check.run(_config(), clients)
        assert any("public endpoint" in e["description"].lower() for e in result)


class TestConfig:
    def test_no_config(self):
        config_mock = MagicMock()
        config_mock.describe_configuration_recorders.side_effect = ClientError(
            {"Error": {"Code": "NoSuchConfigurationRecorderException"}}, "describe_configuration_recorders"
        )

        clients = MagicMock()
        clients.get = lambda name: config_mock if name == "config" else MagicMock()

        result = config_check.run(_config(), clients)
        assert any("not configured" in e["description"].lower() for e in result)

    def test_not_recording(self):
        config_mock = MagicMock()
        config_mock.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{"name": "default"}]
        }
        config_mock.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"recording": False}]
        }

        clients = MagicMock()
        clients.get = lambda name: config_mock if name == "config" else MagicMock()

        result = config_check.run(_config(), clients)
        assert any("not recording" in e["description"].lower() for e in result)

