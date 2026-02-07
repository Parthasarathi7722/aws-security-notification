"""Tests for config module."""
import os
import pytest
from security_notifier.config import Config, safe_get, is_whitelisted, is_critical_event


class TestConfig:
    def test_loads_webhook_url(self, config):
        assert config.slack_webhook_url == "https://hooks.slack.com/test"

    def test_missing_webhook_raises(self, monkeypatch):
        monkeypatch.delenv("SLACK_WEBHOOK_URL")
        with pytest.raises(ValueError, match="SLACK_WEBHOOK_URL is required"):
            Config()

    def test_account_name(self, config):
        assert config.account_name == "TestAccount"

    def test_whitelist_parsing(self, config):
        assert config.whitelist_resources == [
            "arn:aws:iam::123456789012:user/deployer"
        ]

    def test_critical_events_parsing(self, config):
        assert config.critical_events == ["CreateUser", "DeleteUser"]

    def test_feature_flags_default_off(self, config):
        assert config.enable_guardduty is False
        assert config.enable_securityhub is False

    def test_feature_flags_enabled(self, monkeypatch):
        monkeypatch.setenv("ENABLE_GUARDDUTY", "true")
        c = Config()
        assert c.enable_guardduty is True

    def test_settings_defaults(self, config):
        assert config.max_retries == 3
        assert config.retry_delay == 2
        assert config.rate_limit == 30
        assert config.max_message_length == 3000


class TestSafeGet:
    def test_nested_value(self):
        d = {"a": {"b": {"c": 42}}}
        assert safe_get(d, "a", "b", "c") == 42

    def test_missing_key(self):
        d = {"a": {"b": 1}}
        assert safe_get(d, "a", "x") is None

    def test_none_input(self):
        assert safe_get(None, "a") is None

    def test_single_key(self):
        assert safe_get({"key": "val"}, "key") == "val"


class TestIsWhitelisted:
    def test_exact_match(self, config):
        assert is_whitelisted(config, "arn:aws:iam::123456789012:user/deployer") is True

    def test_no_match(self, config):
        assert is_whitelisted(config, "arn:aws:iam::999999999999:user/hacker") is False

    def test_none_arn(self, config):
        assert is_whitelisted(config, None) is False

    def test_unknown_arn(self, config):
        assert is_whitelisted(config, "Unknown ARN") is False

    def test_wildcard(self, monkeypatch):
        monkeypatch.setenv("WHITELIST_RESOURCES", "arn:aws:iam::123*")
        c = Config()
        assert is_whitelisted(c, "arn:aws:iam::123456789012:user/anyone") is True


class TestIsCriticalEvent:
    def test_critical_event(self, config):
        assert is_critical_event(config, "CreateUser") is True

    def test_non_critical_event(self, config):
        assert is_critical_event(config, "DescribeInstances") is False

    def test_none_event(self, config):
        assert is_critical_event(config, None) is False
