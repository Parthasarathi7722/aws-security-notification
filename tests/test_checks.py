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

