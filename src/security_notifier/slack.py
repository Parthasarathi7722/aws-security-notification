"""Slack notification with retry logic and rate limiting."""
import time
import logging
from datetime import datetime, timezone, timedelta
from collections import deque

import requests

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Sends messages to Slack with retry and rate limiting."""

    def __init__(self, config):
        self.config = config
        self.rate_limiter = deque(maxlen=config.rate_limit)

    def send(self, message, is_critical=False):
        """Send message to Slack with retry and rate limiting."""
        # Truncate long messages
        if len(message) > self.config.max_message_length:
            message = message[:self.config.max_message_length - 50] + "\n...[truncated]"

        if is_critical:
            message = f"\U0001f6a8 *CRITICAL ALERT* \U0001f6a8\n{message}"

        payload = {
            "text": message,
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": message}}],
        }

        for attempt in range(self.config.max_retries):
            try:
                # Rate limit check
                now = datetime.now(timezone.utc)
                while self.rate_limiter and self.rate_limiter[0] < now - timedelta(seconds=60):
                    self.rate_limiter.popleft()

                if len(self.rate_limiter) >= self.config.rate_limit:
                    time.sleep(1)
                    continue

                response = requests.post(
                    self.config.slack_webhook_url, json=payload, timeout=10
                )
                self.rate_limiter.append(now)

                if response.status_code == 200:
                    return True
                elif response.status_code == 429:
                    time.sleep(
                        int(response.headers.get("Retry-After", self.config.retry_delay))
                    )
                else:
                    if attempt < self.config.max_retries - 1:
                        time.sleep(self.config.retry_delay * (attempt + 1))
            except Exception as e:
                logger.error(f"Slack error (attempt {attempt + 1}): {e}")
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))

        return False
