"""Tests for Lambda handler."""
import json
from unittest.mock import patch, MagicMock
from security_notifier.handler import lambda_handler


def _sqs_event(*details):
    """Build a mock SQS event with the given CloudTrail detail dicts."""
    records = []
    for detail in details:
        records.append({"body": json.dumps({"detail": detail})})
    return {"Records": records}


class TestLambdaHandler:
    @patch("security_notifier.handler.SlackNotifier")
    @patch("security_notifier.handler.ClientFactory")
    def test_processes_single_event(self, mock_cf, mock_sn_cls):
        mock_notifier = MagicMock()
        mock_notifier.send.return_value = True
        mock_sn_cls.return_value = mock_notifier

        event = _sqs_event({
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "userName": "admin", "arn": "arn:aws:iam::123:user/admin"},
        })
        ctx = MagicMock()
        ctx.request_id = "test-123"

        result = lambda_handler(event, ctx)
        assert result["statusCode"] == 200
        mock_notifier.send.assert_called()

    @patch("security_notifier.handler.SlackNotifier")
    @patch("security_notifier.handler.ClientFactory")
    def test_whitelisted_event_filtered(self, mock_cf, mock_sn_cls):
        mock_notifier = MagicMock()
        mock_sn_cls.return_value = mock_notifier

        event = _sqs_event({
            "eventName": "CreateUser",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/deployer"},
        })
        ctx = MagicMock()
        ctx.request_id = "test-456"

        result = lambda_handler(event, ctx)
        assert result["statusCode"] == 200
        # Whitelisted events should not trigger Slack notifications
        mock_notifier.send.assert_not_called()

    @patch("security_notifier.handler.SlackNotifier")
    @patch("security_notifier.handler.ClientFactory")
    def test_groups_same_events(self, mock_cf, mock_sn_cls):
        mock_notifier = MagicMock()
        mock_notifier.send.return_value = True
        mock_sn_cls.return_value = mock_notifier

        detail = {
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111:user/test"},
            "resources": [{"ARN": "arn:aws:iam::111:user/newuser"}],
        }
        event = _sqs_event(detail, detail, detail)
        ctx = MagicMock()
        ctx.request_id = "test-789"

        result = lambda_handler(event, ctx)
        assert result["statusCode"] == 200
        # Grouped into 1 call, should show "Aggregated Alert"
        call_args = mock_notifier.send.call_args_list[0]
        assert "Aggregated Alert" in call_args[0][0]

    @patch("security_notifier.handler.SlackNotifier")
    @patch("security_notifier.handler.ClientFactory")
    def test_empty_event(self, mock_cf, mock_sn_cls):
        mock_notifier = MagicMock()
        mock_sn_cls.return_value = mock_notifier

        result = lambda_handler({"Records": []}, MagicMock(request_id="x"))
        assert result["statusCode"] == 200

    @patch("security_notifier.handler.SlackNotifier")
    @patch("security_notifier.handler.ClientFactory")
    def test_bad_record_handled(self, mock_cf, mock_sn_cls):
        mock_notifier = MagicMock()
        mock_sn_cls.return_value = mock_notifier

        event = {"Records": [{"body": "not json"}]}
        ctx = MagicMock()
        ctx.request_id = "err-test"

        result = lambda_handler(event, ctx)
        assert result["statusCode"] == 200

    @patch("security_notifier.handler.SlackNotifier")
    @patch("security_notifier.handler.ClientFactory")
    def test_critical_event_flagged(self, mock_cf, mock_sn_cls):
        mock_notifier = MagicMock()
        mock_notifier.send.return_value = True
        mock_sn_cls.return_value = mock_notifier

        event = _sqs_event({
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111:user/x"},
        })
        ctx = MagicMock()
        ctx.request_id = "crit-test"

        lambda_handler(event, ctx)
        # CreateUser is in CRITICAL_EVENTS, so is_critical should be True
        call_args = mock_notifier.send.call_args_list[0]
        assert call_args[0][1] is True  # is_critical arg
