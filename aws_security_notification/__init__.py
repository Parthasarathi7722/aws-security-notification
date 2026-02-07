# Expose the Lambda handler for library usage
from security_notifier.handler import lambda_handler

__all__ = ["lambda_handler"]
