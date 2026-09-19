"""
Sentinel-12 Python SDK Core Client
Provides a programmatic Python API for security test automation and CI/CD integration
"""

import sys
import os
import json
from typing import Dict, List, Optional, Any, Union

# Ensure root directory is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from base_test import Severity, Finding
from runner import SecurityTestSuite, load_config


class SecurityAssertionError(AssertionError):
    """Raised when security assertions (e.g. no critical findings) fail"""
    pass


class SentinelConfig:
    """Configuration builder for Sentinel SDK Client"""
    
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        admin_session: Optional[str] = None,
        user_a_session: Optional[str] = None,
        user_b_session: Optional[str] = None,
        agency_a_session: Optional[str] = None,
        agency_b_session: Optional[str] = None,
        verbose: bool = False,
        timeout: int = 10,
        delay: float = 0.1
    ):
        self.base_url = base_url.rstrip('/')
        self.admin_session = admin_session
        self.user_a_session = user_a_session
        self.user_b_session = user_b_session
        self.agency_a_session = agency_a_session
        self.agency_b_session = agency_b_session
        self.verbose = verbose
        self.timeout = timeout
        self.delay = delay

    def to_dict(self) -> Dict[str, Any]:
        return {
            'base_url': self.base_url,
            'admin_session': self.admin_session,
            'user_a_session': self.user_a_session,
            'user_b_session': self.user_b_session,
            'agency_a_session': self.agency_a_session,
            'agency_b_session': self.agency_b_session,
            'verbose': self.verbose,
            'test_config': {
                'request_timeout': self.timeout,
                'request_delay': self.delay
            }
        }


class SentinelClient:
    """
    Sentinel-12 Security Suite SDK Client
    
    Example Usage:
    ```python
    from sentinel_sdk import SentinelClient
    
    client = SentinelClient(base_url="http://127.0.0.1:8000")
    client.set_session('admin', 'admin_session_cookie')
    client.run_all()
    
    # Assert security standards in CI/CD pipeline
    client.assert_no_critical_vulnerabilities()
    ```
    """
    
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        config_file: Optional[str] = None,
        verbose: bool = False
    ):
        if config_file:
            raw_config = load_config(config_file)
            self.config = raw_config
        else:
            self.config = SentinelConfig(base_url=base_url, verbose=verbose).to_dict()
            
        self.suite: Optional[SecurityTestSuite] = None
        self.last_results: List[Finding] = []

    def set_session(self, role: str, session_cookie: str) -> "SentinelClient":
        """
        Configure session cookie for a specific role
        Roles: 'admin', 'user_a', 'user_b', 'agency_a', 'agency_b'
        """
        key_map = {
            'admin': 'admin_session',
            'user_a': 'user_a_session',
            'user_b': 'user_b_session',
            'agency_a': 'agency_a_session',
            'agency_b': 'agency_b_session'
        }
        
        target_key = key_map.get(role, f"{role}_session")
        self.config[target_key] = session_cookie
        return self

    def run_modules(self, modules: List[str]) -> List[Finding]:
        """Run specific security test modules by name"""
        self.suite = SecurityTestSuite(self.config)
        self.suite.run_all_tests(selected_modules=modules)
        self.last_results = self.suite.all_findings
        return self.last_results

    def run_all(self) -> List[Finding]:
        """Run all 12 security test modules"""
        self.suite = SecurityTestSuite(self.config)
        self.suite.run_all_tests(selected_modules=None)
        self.last_results = self.suite.all_findings
        return self.last_results

    def get_findings(self, severity: Optional[Union[Severity, str]] = None) -> List[Finding]:
        """Return findings filtered by severity level"""
        if not severity:
            return self.last_results
            
        target_val = severity.value if isinstance(severity, Severity) else str(severity).lower()
        return [f for f in self.last_results if f.severity.value == target_val]

    def calculate_risk_score(self) -> int:
        """Calculate aggregate risk score"""
        counts = {
            'critical': len(self.get_findings(Severity.CRITICAL)),
            'high': len(self.get_findings(Severity.HIGH)),
            'medium': len(self.get_findings(Severity.MEDIUM)),
            'low': len(self.get_findings(Severity.LOW))
        }
        
        return (counts['critical'] * 10) + (counts['high'] * 5) + (counts['medium'] * 2) + (counts['low'] * 1)

    def assert_no_critical_vulnerabilities(self):
        """CI/CD Assertion: Raises SecurityAssertionError if any CRITICAL vulnerabilities are found"""
        critical_findings = self.get_findings(Severity.CRITICAL)
        if critical_findings:
            msg = f"Security Assertion Failed: {len(critical_findings)} CRITICAL vulnerabilities detected:\n"
            for f in critical_findings:
                msg += f"  - [{f.message}] Endpoint: {f.details.get('endpoint', 'N/A')}\n"
            raise SecurityAssertionError(msg)

    def assert_max_risk_score(self, max_allowed: int = 10):
        """CI/CD Assertion: Raises SecurityAssertionError if total Risk Score exceeds threshold"""
        score = self.calculate_risk_score()
        if score > max_allowed:
            raise SecurityAssertionError(
                f"Security Assertion Failed: Risk score ({score}) exceeds maximum allowed threshold ({max_allowed})."
            )

    def export_json(self, output_file: str):
        """Export findings to a JSON file"""
        if self.suite:
            self.suite.export_json(output_file)

    def export_html(self, output_file: str):
        """Export findings to an interactive HTML report"""
        if self.suite:
            self.suite.export_html(output_file)
