"""Tests for security check modules."""
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from security_notifier.checks import guardduty, securityhub, iam, cloudtrail


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


class TestConfigCompliance:
    def test_all_compliant(self):
        cfg_mock = MagicMock()
        cfg_mock.describe_config_rules.return_value = {
            "ConfigRules": [{"ConfigRuleName": "rule1"}]
        }
        cfg_mock.get_compliance_details_by_config_rule.return_value = {
            "EvaluationResults": [{"ComplianceType": "COMPLIANT"}]
        }
        clients = MagicMock()
        clients.get = lambda name: cfg_mock if name == "config" else MagicMock()
        assert config_compliance.run(_config(), clients) == []

    def test_non_compliant(self):
        cfg_mock = MagicMock()
        cfg_mock.describe_config_rules.return_value = {
            "ConfigRules": [{"ConfigRuleName": "rule1"}]
        }
        cfg_mock.get_compliance_details_by_config_rule.return_value = {
            "EvaluationResults": [{"ComplianceType": "NON_COMPLIANT"}]
        }
        clients = MagicMock()
        clients.get = lambda name: cfg_mock if name == "config" else MagicMock()
        result = config_compliance.run(_config(), clients)
        assert len(result) == 1
        assert result[0]["severity"] == "HIGH"


class TestECS:
    def test_active_cluster(self):
        clients = _mock_clients({
            "ecs": {
                "list_clusters": {"clusterArns": ["arn:cluster1"]},
                "describe_clusters": {"clusters": [{"clusterName": "c1", "status": "ACTIVE"}]},
            }
        })
        assert ecs.run(_config(), clients) == []

    def test_inactive_cluster(self):
        clients = _mock_clients({
            "ecs": {
                "list_clusters": {"clusterArns": ["arn:cluster1"]},
                "describe_clusters": {"clusters": [{"clusterName": "c1", "status": "INACTIVE"}]},
            }
        })
        result = ecs.run(_config(), clients)
        assert len(result) == 1
        assert result[0]["severity"] == "HIGH"


class TestEKS:
    def test_public_access(self):
        clients = _mock_clients({
            "eks": {
                "list_clusters": {"clusters": ["cluster1"]},
                "describe_cluster": {
                    "cluster": {
                        "status": "ACTIVE",
                        "resourcesVpcConfig": {"endpointPublicAccess": True},
                    }
                },
            }
        })
        result = eks.run(_config(), clients)
        assert any(e["severity"] == "MEDIUM" for e in result)


class TestRDS:
    def test_public_and_unencrypted(self):
        clients = _mock_clients({
            "rds": {
                "describe_db_instances": {
                    "DBInstances": [{
                        "DBInstanceIdentifier": "db1",
                        "PubliclyAccessible": True,
                        "StorageEncrypted": False,
                        "BackupRetentionPeriod": 7,
                        "DeletionProtection": True,
                    }]
                }
            }
        })
        result = rds.run(_config(), clients)
        critical = [e for e in result if e["severity"] == "CRITICAL"]
        assert len(critical) == 2  # public + unencrypted

    def test_healthy_db(self):
        clients = _mock_clients({
            "rds": {
                "describe_db_instances": {
                    "DBInstances": [{
                        "DBInstanceIdentifier": "db1",
                        "PubliclyAccessible": False,
                        "StorageEncrypted": True,
                        "BackupRetentionPeriod": 7,
                        "DeletionProtection": True,
                    }]
                }
            }
        })
        assert rds.run(_config(), clients) == []


class TestS3:
    def test_no_public_block(self):
        s3_mock = MagicMock()
        s3_mock.list_buckets.return_value = {"Buckets": [{"Name": "bucket1"}]}
        error_response = {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}
        s3_mock.get_public_access_block.side_effect = ClientError(error_response, "GetPublicAccessBlock")
        s3_mock.get_bucket_encryption.return_value = {}
        s3_mock.get_bucket_versioning.return_value = {"Status": "Enabled"}

        clients = MagicMock()
        clients.get = lambda name: s3_mock if name == "s3" else MagicMock()

        result = s3.run(_config(), clients)
        assert any(e["severity"] == "CRITICAL" for e in result)


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


class TestKMS:
    def test_no_rotation(self):
        kms_mock = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Keys": [{"KeyId": "key-1"}]}]
        kms_mock.get_paginator.return_value = paginator
        kms_mock.describe_key.return_value = {
            "KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled", "Arn": "arn:key-1"}
        }
        kms_mock.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}

        clients = MagicMock()
        clients.get = lambda name: kms_mock if name == "kms" else MagicMock()

        result = kms.run(_config(), clients)
        assert len(result) == 1
        assert result[0]["severity"] == "MEDIUM"


class TestSecrets:
    def test_no_rotation(self):
        sm_mock = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"SecretList": [{"Name": "secret1", "RotationEnabled": False}]}
        ]
        sm_mock.get_paginator.return_value = paginator

        clients = MagicMock()
        clients.get = lambda name: sm_mock if name == "secretsmanager" else MagicMock()

        result = secrets.run(_config(), clients)
        assert len(result) == 1
        assert result[0]["severity"] == "MEDIUM"
