"""
Sentinel-12 Security Protocol Python SDK
Programmatic security testing and CI/CD audit automation
"""

from sentinel_sdk.client import (
    SentinelClient,
    SentinelConfig,
    SecurityAssertionError,
    Finding,
    Severity
)

__version__ = "2.0.0"
__all__ = [
    "SentinelClient",
    "SentinelConfig",
    "SecurityAssertionError",
    "Finding",
    "Severity"
]
