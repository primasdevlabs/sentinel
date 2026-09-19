"""
Pytest Plugin Fixture for Sentinel-12 Security Suite
Allows simple pytest integration: `def test_app_security(sentinel_client): ...`
"""

import pytest
import os
from sentinel_sdk.client import SentinelClient


@pytest.fixture
def sentinel_client():
    """
    Pytest fixture supplying an initialized SentinelClient.
    Reads SENTINEL_BASE_URL and SENTINEL_CONFIG env variables if present.
    """
    base_url = os.environ.get("SENTINEL_BASE_URL", "http://127.0.0.1:8000")
    config_file = os.environ.get("SENTINEL_CONFIG", None)
    
    client = SentinelClient(base_url=base_url, config_file=config_file)
    return client
