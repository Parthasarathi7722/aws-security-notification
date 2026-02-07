"""AWS Security Notification System."""
__version__ = "3.0.0"

from .handler import lambda_handler

__all__ = ["lambda_handler", "__version__"]
