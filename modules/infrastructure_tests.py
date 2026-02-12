"""
Module 11: Infrastructure & Deployment Security
Tests infrastructure configuration and deployment security
"""

from sentinel.base_test import BaseSecurityTest, Severity


class InfrastructureTests(BaseSecurityTest):
    """Infrastructure & Deployment Security Tests"""
    
    def run_tests(self):
        """Run all infrastructure tests"""
        print("\n" + "="*60)
        print("MODULE 11: INFRASTRUCTURE & DEPLOYMENT SECURITY")
        print("="*60)
        
        self.test_debug_mode_exposure()
        self.test_sensitive_file_exposure()
        self.test_test_routes_in_prod()
    
    def test_debug_mode_exposure(self):
        """Test for debug mode exposure"""
        print("\n[TEST] Debug Mode Exposure")
        
        # Trigger an error to see if debug info is exposed
        r = self.request(self.sessions['unauthenticated'], "GET",
                       "/nonexistent-route-12345")
        
        if r and "APP_KEY" in r.text or "Whoops" in r.text:
            self.log(Severity.CRITICAL,
                    "Debug mode enabled in production (stack traces exposed)")
        elif r and r.status_code == 404:
            self.log(Severity.PASSED, "Debug mode properly disabled")
    
    def test_sensitive_file_exposure(self):
        """Test for sensitive file exposure"""
        print("\n[TEST] Sensitive File Exposure")
        
        sensitive_files = [
            ".env",
            ".git/config",
            "storage/logs/laravel.log",
            "composer.json",
            "phpinfo.php"
        ]
        
        for file_path in sensitive_files:
            r = self.request(self.sessions['unauthenticated'], "GET",
                           f"/{file_path}", allow_redirects=False)
            
            if r and r.status_code == 200:
                if "APP_KEY" in r.text or "[core]" in r.text:
                    self.log(Severity.CRITICAL,
                            f"Sensitive file exposed: {file_path}")
                else:
                    self.log(Severity.MEDIUM,
                            f"File accessible: {file_path}")
            else:
                self.log(Severity.PASSED, f"File protected: {file_path}")
    
    def test_test_routes_in_prod(self):
        """Test for test routes in production"""
        print("\n[TEST] Test Routes in Production")
        
        test_routes = [
            "/test",
            "/debug",
            "/_debug",
            "/api/test",
            "/telescope"
        ]
        
        for route in test_routes:
            r = self.request(self.sessions['unauthenticated'], "GET", route)
            
            if r and r.status_code == 200:
                self.log(Severity.HIGH,
                        f"Test/debug route accessible: {route}")
            else:
                self.log(Severity.PASSED, f"Test route not accessible: {route}")
