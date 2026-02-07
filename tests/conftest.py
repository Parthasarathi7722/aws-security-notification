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
    # Disable all core checks by default in tests
    monkeypatch.setenv("ENABLE_GUARDDUTY", "false")
    monkeypatch.setenv("ENABLE_SECURITYHUB", "false")
    monkeypatch.setenv("ENABLE_IAM", "false")
    monkeypatch.setenv("ENABLE_CLOUDTRAIL", "false")


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
