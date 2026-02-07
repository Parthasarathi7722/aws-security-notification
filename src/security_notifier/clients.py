"""Lazy boto3 client factory - only creates clients when first accessed."""
import boto3


class ClientFactory:
    """Creates boto3 clients on demand and caches them."""

    def __init__(self):
        self._clients = {}

    def get(self, service_name):
        """Get or create a boto3 client for the given service."""
        if service_name not in self._clients:
            self._clients[service_name] = boto3.client(service_name)
        return self._clients[service_name]
