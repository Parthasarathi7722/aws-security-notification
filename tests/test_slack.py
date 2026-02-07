"""Tests for Slack notifier."""
from unittest.mock import patch, MagicMock
from security_notifier.slack import SlackNotifier
from security_notifier.metrics import new_metrics


class TestSlackNotifier:
    def test_send_success(self, config):
        notifier = SlackNotifier(config)
        metrics = new_metrics()
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("security_notifier.slack.requests.post", return_value=mock_response):
            result = notifier.send("test message", metrics=metrics)

        assert result is True
        assert metrics["notifications_sent"] == 1

    def test_send_failure(self, config):
        notifier = SlackNotifier(config)
        metrics = new_metrics()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.headers = {}

        with patch("security_notifier.slack.requests.post", return_value=mock_response):
            with patch("security_notifier.slack.time.sleep"):
                result = notifier.send("test message", metrics=metrics)

        assert result is False
        assert metrics["notifications_failed"] == 1

    def test_truncation(self, config):
        config.max_message_length = 100
        notifier = SlackNotifier(config)
        mock_response = MagicMock()
        mock_response.status_code = 200
        long_message = "x" * 200

        with patch("security_notifier.slack.requests.post", return_value=mock_response) as mock_post:
            notifier.send(long_message)

        sent_payload = mock_post.call_args[1]["json"]
        assert "[truncated]" in sent_payload["text"]
        assert len(sent_payload["text"]) <= 100

    def test_critical_prefix(self, config):
        notifier = SlackNotifier(config)
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("security_notifier.slack.requests.post", return_value=mock_response) as mock_post:
            notifier.send("alert!", is_critical=True)

        sent_payload = mock_post.call_args[1]["json"]
        assert "CRITICAL ALERT" in sent_payload["text"]

    def test_retry_on_exception(self, config):
        config.max_retries = 2
        config.retry_delay = 0
        notifier = SlackNotifier(config)
        metrics = new_metrics()

        with patch("security_notifier.slack.requests.post", side_effect=Exception("network")):
            with patch("security_notifier.slack.time.sleep"):
                result = notifier.send("test", metrics=metrics)

        assert result is False
        assert metrics["notifications_failed"] == 1

    def test_rate_limiting(self, config):
        config.rate_limit = 1
        notifier = SlackNotifier(config)
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("security_notifier.slack.requests.post", return_value=mock_response):
            notifier.send("msg1")
            # Second message should hit rate limit
            with patch("security_notifier.slack.time.sleep"):
                notifier.send("msg2")
