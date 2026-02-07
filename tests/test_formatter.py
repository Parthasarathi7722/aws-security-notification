"""Tests for formatter module."""
from security_notifier.formatter import format_event_message


class TestFormatEventMessage:
    def test_basic_formatting(self, config):
        detail = {
            "eventName": "CreateUser",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "admin",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/admin",
            },
            "sourceIPAddress": "1.2.3.4",
            "awsRegion": "us-east-1",
            "eventTime": "2025-01-01T00:00:00Z",
        }
        msg = format_event_message(config, detail)
        assert "TestAccount" in msg
        assert "CreateUser" in msg
        assert "admin" in msg
        assert "1.2.3.4" in msg
        assert "us-east-1" in msg

    def test_no_mfa_risk(self, config):
        detail = {
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "userName": "user1"},
        }
        msg = format_event_message(config, detail)
        assert "No MFA" in msg

    def test_root_risk(self, config):
        detail = {
            "eventName": "CreateUser",
            "userIdentity": {"type": "Root"},
        }
        msg = format_event_message(config, detail)
        assert "Root account" in msg

    def test_error_code_risk(self, config):
        detail = {
            "eventName": "CreateUser",
            "errorCode": "AccessDenied",
            "userIdentity": {"type": "IAMUser"},
        }
        msg = format_event_message(config, detail)
        assert "Denied: AccessDenied" in msg

    def test_missing_fields(self, config):
        detail = {}
        msg = format_event_message(config, detail)
        assert "Unknown" in msg

    def test_mfa_authenticated_no_risk(self, config):
        detail = {
            "eventName": "CreateUser",
            "userIdentity": {
                "type": "IAMUser",
                "sessionContext": {
                    "attributes": {"mfaAuthenticated": "true"},
                },
            },
        }
        msg = format_event_message(config, detail)
        assert "No MFA" not in msg
