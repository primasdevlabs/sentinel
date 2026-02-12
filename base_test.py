"""
Base Security Test Class
Provides common functionality for all security test modules
"""

import requests
import time
import json
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
from enum import Enum


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASSED = "passed"


class Finding:
    """Represents a security finding"""
    def __init__(self, severity: Severity, message: str, details: Optional[Dict] = None):
        self.severity = severity
        self.message = message
        self.details = details or {}
        self.timestamp = time.time()
    
    def to_dict(self):
        return {
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp
        }


class BaseSecurityTest:
    """Base class for all security test modules"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config['base_url'].rstrip('/')
        self.findings: List[Finding] = []
        self.sessions = self._initialize_sessions()
        self.csrf_tokens = {}
        
    def _initialize_sessions(self) -> Dict[str, requests.Session]:
        """Initialize all test sessions"""
        sessions = {}
        
        session_configs = {
            'admin': self.config.get('admin_session'),
            'user_a': self.config.get('user_a_session'),
            'user_b': self.config.get('user_b_session'),
            'agency_a': self.config.get('agency_a_session'),
            'agency_b': self.config.get('agency_b_session'),
            'unauthenticated': None
        }
        
        for name, cookie in session_configs.items():
            session = requests.Session()
            if cookie:
                session.cookies.set('laravel_session', cookie)
            sessions[name] = session
            
        return sessions
    
    def get_csrf_token(self, session: requests.Session) -> Optional[str]:
        """Extract CSRF token for a session"""
        session_id = id(session)
        
        if session_id in self.csrf_tokens:
            return self.csrf_tokens[session_id]
            
        try:
            r = session.get(self.base_url, timeout=10)
            if r and r.status_code == 200:
                match = re.search(r'meta name="csrf-token" content="([^"]+)"', r.text)
                if match:
                    token = match.group(1)
                    self.csrf_tokens[session_id] = token
                    return token
        except Exception as e:
            self.log(Severity.INFO, f"Failed to get CSRF token: {e}")
        
        return None
    
    def request(self, session: requests.Session, method: str, path: str, 
                allow_redirects: bool = True, **kwargs) -> Optional[requests.Response]:
        """Make an HTTP request with proper headers and CSRF handling"""
        url = urljoin(self.base_url, path)
        headers = kwargs.pop('headers', {})
        
        # Add CSRF token for state-changing methods
        if method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
            token = self.get_csrf_token(session)
            if token:
                headers['X-CSRF-TOKEN'] = token
            headers['Accept'] = 'application/json'
        
        try:
            r = session.request(
                method, 
                url, 
                timeout=kwargs.pop('timeout', 10),
                allow_redirects=allow_redirects,
                headers=headers,
                **kwargs
            )
            return r
        except requests.exceptions.RequestException as e:
            self.log(Severity.INFO, f"Request failed: {method} {path} - {e}")
            return None
    
    def log(self, severity: Severity, message: str, details: Optional[Dict] = None):
        """Log a finding"""
        finding = Finding(severity, message, details)
        self.findings.append(finding)
        
        # Console output
        icons = {
            Severity.CRITICAL: "🔥",
            Severity.HIGH: "🚨",
            Severity.MEDIUM: "⚠️",
            Severity.LOW: "ℹ️",
            Severity.INFO: "💡",
            Severity.PASSED: "✅"
        }
        
        icon = icons.get(severity, "📝")
        print(f"{icon} [{severity.value.upper()}] {message}")
        
        if details and self.config.get('verbose', False):
            print(f"   Details: {json.dumps(details, indent=2)}")
    
    def run_tests(self):
        """Override this method in subclasses to run specific tests"""
        raise NotImplementedError("Subclasses must implement run_tests()")
    
    def get_findings(self) -> List[Finding]:
        """Return all findings"""
        return self.findings
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary of findings by severity"""
        summary = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary
