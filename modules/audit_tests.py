"""
Module 9: Logging, Audit & Forensics
Tests logging, audit trails, and forensic capabilities
"""

from pentest.base_test import BaseSecurityTest, Severity


class AuditSecurityTests(BaseSecurityTest):
    """Logging, Audit & Forensics Tests"""
    
    def run_tests(self):
        """Run all audit tests"""
        print("\n" + "="*60)
        print("MODULE 9: LOGGING, AUDIT & FORENSICS")
        print("="*60)
        
        self.test_security_event_logging()
        self.test_log_injection()
    
    def test_security_event_logging(self):
        """Test security event logging"""
        print("\n[TEST] Security Event Logging")
        
        self.log(Severity.INFO,
                "Security event logging test requires log access")
        self.log(Severity.INFO,
                "Manual verification: Perform sensitive action → Check logs for entry")
    
    def test_log_injection(self):
        """Test log injection attacks"""
        print("\n[TEST] Log Injection")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Try to inject newlines into logs
        injection_payload = "test\n[CRITICAL] Fake log entry"
        
        r = self.request(self.sessions['user_a'], "POST",
                       "/api/v1/test",
                       json={"name": injection_payload})
        
        self.log(Severity.INFO,
                "Log injection test requires log file access to verify")
