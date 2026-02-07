"""Shared test fixtures."""
import os
import pytest
from unittest.mock import MagicMock


@pytest.fixture(autouse=True)
def env_vars(monkeypatch):
    """Set required environment variables for all tests."""
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
    monkeypatch.setenv("ACCOUNT_NAME", "TestAccount")
    monkeypatch.setenv("WHITELIST_RESOURCES", "arn:aws:iam::123456789012:user/deployer")
    monkeypatch.setenv("CRITICAL_EVENTS", "CreateUser,DeleteUser")
    # Disable all checks by default in tests
    monkeypatch.setenv("ENABLE_GUARDDUTY", "false")
    monkeypatch.setenv("ENABLE_SECURITYHUB", "false")
    monkeypatch.setenv("ENABLE_CONFIG", "false")
    monkeypatch.setenv("ENABLE_ECS", "false")
    monkeypatch.setenv("ENABLE_EKS", "false")
    monkeypatch.setenv("ENABLE_RDS", "false")
    monkeypatch.setenv("ENABLE_LAMBDA_CHECKS", "false")
    monkeypatch.setenv("ENABLE_IAM_CHECKS", "false")
    monkeypatch.setenv("ENABLE_S3_CHECKS", "false")
    monkeypatch.setenv("ENABLE_CLOUDTRAIL_CHECKS", "false")
    monkeypatch.setenv("ENABLE_KMS_CHECKS", "false")
    monkeypatch.setenv("ENABLE_SECRETS_CHECKS", "false")


@pytest.fixture
def config():
    """Create a Config instance with test env vars."""
    from security_notifier.config import Config
    return Config()


@pytest.fixture
def mock_clients():
    """Create a mock ClientFactory."""
    from security_notifier.clients import ClientFactory
    factory = ClientFactory()
    factory._clients = {}

    class MockClientFactory:
        def __init__(self):
            self._mocks = {}

        def get(self, service_name):
            if service_name not in self._mocks:
                self._mocks[service_name] = MagicMock()
            return self._mocks[service_name]

    return MockClientFactory()
